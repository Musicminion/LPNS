// SPDX-License-Identifier: GPL-2.0+
/*
 * NVMe IO command translation and polling IO thread
 * Copyright (c) 2019 - Maxim Levitsky
 */
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/nvme.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>
#include <asm/msr.h>
#include "priv.h"

#define DEBUG	1

struct io_ctx {
	struct nvme_mdev_hctrl *hctrl;
	struct nvme_mdev_vctrl *vctrl;

	const struct nvme_command *in;
	struct nvme_command out;
	struct nvme_mdev_vns *ns;
	struct nvme_ext_data_iter udatait;
	struct nvme_ext_data_iter *kdatait;

	ktime_t last_io_t;
	ktime_t last_admin_poll_time;
	unsigned int idle_timeout_ms;
	unsigned int admin_poll_rate_ms;
	unsigned int arb_burst;
};

/* Handle read/write command.*/
static int nvme_mdev_io_translate_rw(struct io_ctx *ctx)
{
	int ret;
	const struct nvme_rw_command *in = &ctx->in->rw;

	u64 slba = le64_to_cpu(in->slba);
	u64 length = le16_to_cpu(in->length) + 1;
	u16 control = le16_to_cpu(in->control);

	_DBG(ctx->vctrl, "IOQ: READ/WRITE\n");

	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_DW23 | RSRV_MPTR | RSRV_DW14_15))
		return DNR(NVME_SC_INVALID_FIELD);

	if (!check_reserved_dwords(ctx->in->dwords, 16, 0b1100000000111100))
		return DNR(NVME_SC_INVALID_FIELD);

	if (in->opcode == nvme_cmd_write && ctx->ns->readonly)
		return DNR(NVME_SC_READ_ONLY);

	if (!check_range(slba, length, ctx->ns->ns_size))
		return DNR(NVME_SC_LBA_RANGE);

	ctx->out.rw.slba = cpu_to_le64(slba + ctx->ns->host_lba_offset);
	ctx->out.rw.length = in->length;

	ret = nvme_mdev_udata_iter_set_dptr(&ctx->udatait, &in->dptr,
					    length << ctx->ns->blksize_shift);
	if (ret)
		return nvme_mdev_translate_error(ret);

	ctx->kdatait = &ctx->udatait;
	if (control & ~(NVME_RW_LR | NVME_RW_FUA))
		return DNR(NVME_SC_INVALID_FIELD);

	ctx->out.rw.control = in->control;
	return -1;
}

/*Handle flush command */
static int nvme_mdev_io_translate_flush(struct io_ctx *ctx)
{
	ctx->kdatait = NULL;

	_DBG(ctx->vctrl, "IOQ: FLUSH\n");

	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_DW23 | RSRV_DPTR |
				   RSRV_MPTR | RSRV_DW10_15))
		return DNR(NVME_SC_INVALID_FIELD);

	if (ctx->ns->readonly)
		return DNR(NVME_SC_READ_ONLY);

	return -1;
}

/* Handle write zeros command */
static int nvme_mdev_io_translate_write_zeros(struct io_ctx *ctx)
{
	const struct nvme_write_zeroes_cmd *in = &ctx->in->write_zeroes;
	u64 slba = le64_to_cpu(in->slba);
	u64 length = le16_to_cpu(in->length) + 1;
	u16 control = le16_to_cpu(in->control);

	_DBG(ctx->vctrl, "IOQ: WRITE_ZEROS\n");

	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_DW23 | RSRV_DPTR |
				   RSRV_MPTR | RSRV_DW13_15))
		return DNR(NVME_SC_INVALID_FIELD);

	if (!nvme_mdev_hctrl_hq_check_op(ctx->hctrl, in->opcode))
		return DNR(NVME_SC_INVALID_OPCODE);

	if (ctx->ns->readonly)
		return DNR(NVME_SC_READ_ONLY);
	ctx->kdatait = NULL;

	if (!check_range(slba, length, ctx->ns->ns_size))
		return DNR(NVME_SC_LBA_RANGE);

	ctx->out.write_zeroes.slba =
		cpu_to_le64(slba + ctx->ns->host_lba_offset);
	ctx->out.write_zeroes.length = in->length;

	if (control & ~(NVME_RW_LR | NVME_RW_FUA | NVME_WZ_DEAC))
		return DNR(NVME_SC_INVALID_FIELD);

	ctx->out.write_zeroes.control = in->control;
	return -1;
}

/* Handle dataset management command */
static int nvme_mdev_io_translate_dsm(struct io_ctx *ctx)
{
	unsigned int size, i, nr;
	int ret;
	const struct nvme_dsm_cmd *in = &ctx->in->dsm;
	struct nvme_dsm_range *data_ptr;

	_DBG(ctx->vctrl, "IOQ: DSM_MANAGEMENT\n");

	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_DW23 | RSRV_MPTR | RSRV_DW12_15))
		return DNR(NVME_SC_INVALID_FIELD);

	if (le32_to_cpu(in->nr) & 0xFFFFFF00)
		return DNR(NVME_SC_INVALID_FIELD);

	if (!nvme_mdev_hctrl_hq_check_op(ctx->hctrl, in->opcode))
		return DNR(NVME_SC_INVALID_OPCODE);

	if (ctx->ns->readonly)
		return DNR(NVME_SC_READ_ONLY);

	nr = le32_to_cpu(in->nr) + 1;
	size = nr * sizeof(struct nvme_dsm_range);

	ctx->out.dsm.nr = in->nr;
	ret = nvme_mdev_udata_iter_set_dptr(&ctx->udatait, &in->dptr, size);
	if (ret)
		goto error;

	ctx->kdatait = nvme_mdev_kdata_iter_alloc(&ctx->vctrl->viommu, size);
	if (!ctx->kdatait)
		return NVME_SC_INTERNAL;

	_DBG(ctx->vctrl, "IOQ: DSM_MANAGEMENT: NR=%d\n", nr);

	ret = nvme_mdev_read_from_udata(ctx->kdatait->kmem.data, &ctx->udatait,
					size);
	if (ret)
		goto error2;

	data_ptr = (struct nvme_dsm_range *)ctx->kdatait->kmem.data;

	for (i = 0 ; i < nr; i++) {
		u64 slba = le64_to_cpu(data_ptr[i].slba);
		/* looks like not zero based value*/
		u32 nlb = le32_to_cpu(data_ptr[i].nlb);

		if (!check_range(slba, nlb, ctx->ns->ns_size))
			goto error2;

		_DBG(ctx->vctrl, "IOQ: DSM_MANAGEMENT: RANGE 0x%llx-0x%x\n",
		     slba, nlb);

		data_ptr[i].slba = cpu_to_le64(slba + ctx->ns->host_lba_offset);
	}

	ctx->out.dsm.attributes = in->attributes;
	return -1;
error2:
	ctx->kdatait->release(ctx->kdatait);
error:
	return nvme_mdev_translate_error(ret);
}

/* Process one new command in the io queue*/
static int nvme_mdev_io_translate_cmd(struct io_ctx *ctx)
{
	memset(&ctx->out, 0, sizeof(ctx->out));
	/* translate opcode */
	ctx->out.common.opcode = ctx->in->common.opcode;

	/* check flags */
	if (ctx->in->common.flags != 0)
		return DNR(NVME_SC_INVALID_FIELD);

	/* namespace*/
	ctx->ns = nvme_mdev_vns_from_vnsid(ctx->vctrl,
					   le32_to_cpu(ctx->in->rw.nsid));
	if (!ctx->ns) {
		_DBG(ctx->vctrl, "IOQ: invalid NSID\n");
		return DNR(NVME_SC_INVALID_NS);
	}

	if (!ctx->ns->readonly && bdev_read_only(ctx->ns->host_part))
		ctx->ns->readonly = true;

	ctx->out.common.nsid = cpu_to_le32(ctx->ns->host_nsid);

	switch (ctx->in->common.opcode) {
	case nvme_cmd_flush:
		return nvme_mdev_io_translate_flush(ctx);
	case nvme_cmd_read:
		return nvme_mdev_io_translate_rw(ctx);
	case nvme_cmd_write:
		return nvme_mdev_io_translate_rw(ctx);
	case nvme_cmd_write_zeroes:
		return nvme_mdev_io_translate_write_zeros(ctx);
	case nvme_cmd_dsm:
		return nvme_mdev_io_translate_dsm(ctx);
	default:
		return DNR(NVME_SC_INVALID_OPCODE);
	}
}

static bool nvme_mdev_io_process_sq(struct io_ctx *ctx, u16 sqid)
{
	struct nvme_vsq *vsq = &ctx->vctrl->vsqs[sqid];
	u16 ucid;
	int ret;
	unsigned long long c1, c2;
	/* IO schd */
	struct nvme_mdev_perf_data *perf_data;

	c1 = rdtsc();
	// pr_info("io.c: current threshold %d | active #THT %d.\n", schd->threshold, schd->active_mdev_dev_num);

	/* IO schd */
	/*
	if (vsq->wait){
		return false;
	}
	*/
	if (schd && ctx->vctrl->type == QOS_TPT && schd->qos_ddl_client->vctrl
		&& schd->qos_ddl_client->vctrl->perf.cmds_started > 0
		&& ctx->vctrl->perf.cmds_started > schd->qos_ddl_client->vctrl->perf.cmds_started * schd->threshold) {
		return false;
	}
	/* update sq tail once it is processed */
	// vsq->tail = vsq->head;

	/* If host queue is full, we can't process a command
	 * as a command will likely result in passthrough
	 */
	if (!nvme_mdev_hctrl_hq_can_submit(ctx->hctrl, vsq->hsq)){
		return false;
	}


	/* read the command */
	ctx->in = nvme_mdev_vsq_get_cmd(ctx->vctrl, vsq);
	if (!ctx->in){
		return false;
	}
	ucid = le16_to_cpu(ctx->in->common.command_id);
	
	/* IO schd */
	// if(ctx->vctrl->type == QOS_DDL) {
	// 	perf_data = ctx->vctrl->perf_data;
	// 	perf_data->cmds_started_id[perf_data->phase][perf_data->cmds_started[perf_data->phase]] = ucid;
	// 	perf_data->cmds_started_cycles[perf_data->phase][perf_data->cmds_started[perf_data->phase]] = c1;
	// 	// mutex_lock(&perf_data->lock);
	// 	if(perf_data->cmds_started[perf_data->phase] < 999)
	// 		perf_data->cmds_started[perf_data->phase]++;
	// 	// mutex_unlock(&perf_data->lock);
	// }
	

	/* translate the command */
	ret = nvme_mdev_io_translate_cmd(ctx);
	if (ret != -1) {
		_DBG(ctx->vctrl,
		     "IOQ: QID %d CID %d FAILED: status 0x%x (translate)\n",
		     sqid, ucid, ret);
		nvme_mdev_vsq_cmd_done_io(ctx->vctrl, sqid, ucid, ret);
		return true;
	}

	/*passthrough*/
	/* ret = nvme_mdev_hctrl_hq_submit(ctx->hctrl,
					vsq->hsq,
					(((u32)vsq->qid) << 16) | ((u32)ucid),
					&ctx->out,
					ctx->kdatait); */
    /* IO schd */
	ret = nvme_mdev_hctrl_hq_submit(ctx->hctrl,
					vsq->hsq,
					(((u64)vsq->qid) << 48) | ((u64)ucid << 32) | ((u64)ctx->vctrl->id),
					&ctx->out,
					ctx->kdatait);

	if (ret) {
		ret = nvme_mdev_translate_error(ret);

		_DBG(ctx->vctrl,
		     "IOQ: QID %d CID %d FAILED: status 0x%x (host submit)\n",
		     sqid, ucid, ret);

		nvme_mdev_vsq_cmd_done_io(ctx->vctrl, sqid, ucid, ret);
	}

	c2 = rdtsc();

	ctx->vctrl->perf.cmds_started++;
	ctx->vctrl->perf.cycles_send_to_hw += (c2 - c1);

	return true;
}

/* process host replies to the passed through commands */
static int nvme_mdev_io_process_hwq(struct io_ctx *ctx, u16 hwq)
{
	int n, i;
	struct nvme_ext_cmd_result res[16];
	/* IO schd */
	struct nvme_mdev_vctrl *vctrl;
	struct nvme_mdev_perf_data *perf_data;

	unsigned long long c1, c2;

	c1 = rdtsc();

	/* process the completions from the hardware */
	n = nvme_mdev_hctrl_hq_poll(ctx->hctrl, hwq, res, 16);
	if (n == -1)
		return -1;

	for (i = 0; i < n; i++) {
		// u16 qid = res[i].tag >> 16;
		// u16 cid = res[i].tag & 0xFFFF;

        /* IO schd */
		u16 qid = res[i].tag >> 48;
		u16 cid = res[i].tag >> 32;
		unsigned int vctrl_id = res[i].tag & 0xFFFFFFFF;
		u16 status = res[i].status;

		if (status != 0)
			_DBG(ctx->vctrl,
			     "IOQ: QID %d CID %d FAILED: status 0x%x (host response)\n",
			     qid, cid, status);

		// nvme_mdev_vsq_cmd_done_io(ctx->vctrl, qid, cid, status);
		if (ctx->vctrl->id == vctrl_id) {
			vctrl = ctx->vctrl;
			nvme_mdev_vsq_cmd_done_io(ctx->vctrl, qid, cid, status);
		}
		else {
			if (vctrl_id < 0 || vctrl_id > schd->curr_client){
				continue;
			}
			vctrl = schd->clients[vctrl_id]->vctrl;
			nvme_mdev_vsq_cmd_done_io(schd->clients[vctrl_id]->vctrl, qid, cid, status);
		}

		/* IO schd */
		// if(vctrl->type == QOS_DDL){
		// 	perf_data = vctrl->perf_data;
		// 	perf_data->cmds_complete_id[perf_data->phase][perf_data->cmds_complete[perf_data->phase]] = cid;
		// 	perf_data->cmds_complete_cycles[perf_data->phase][perf_data->cmds_complete[perf_data->phase]] = c1;
		// 	// mutex_lock(&perf_data->lock);
		// 	if(perf_data->cmds_complete[perf_data->phase] < 1000 - 1)
		// 		perf_data->cmds_complete[perf_data->phase]++;
		// 	// mutex_unlock(&perf_data->lock);
		// }
	}

	if (n > 0) {
		c2 = rdtsc();
		ctx->vctrl->perf.cmds_complete += n;
		ctx->vctrl->perf.cycles_receive_from_hw += (c2-c1);
	}

	return n;
}

/* Check if we need to read a command from the admin queue */
static bool nvme_mdev_adm_needs_processing(struct io_ctx *ctx)
{
	if (!timeout(ctx->last_admin_poll_time,
		     ctx->vctrl->now, ctx->admin_poll_rate_ms))
		return false;

	if (nvme_mdev_vsq_has_data(ctx->vctrl, &ctx->vctrl->vsqs[0]))
		return true;

	ctx->last_admin_poll_time = ctx->vctrl->now;
	return false;
}

/* do polling till one of events stops it */
static void nvme_mdev_io_maintask(struct io_ctx *ctx)
{
	struct nvme_mdev_vctrl *vctrl = ctx->vctrl;
	u16 i, cqid, sqid, hsqcnt;
	u16 hsqs[MAX_HOST_QUEUES];
	bool idle = false;

	hsqcnt = nvme_mdev_vctrl_hqs_list(vctrl, hsqs);
	ctx->arb_burst = 1 << ctx->vctrl->arb_burst_shift;

	/* can't stop polling when shadow db not enabled */
	ctx->idle_timeout_ms = vctrl->mmio.shadow_db_en ? poll_timeout_ms : 0;
	ctx->admin_poll_rate_ms = admin_poll_rate_ms;

	vctrl->now = ktime_get();
	ctx->last_admin_poll_time = vctrl->now;
	ctx->last_io_t = vctrl->now;

	/* main loop */
	while (!kthread_should_park()) {
		vctrl->now = ktime_get();
	
		/* check if we have to exit to support admin polling */
		if (!vctrl->mmio.shadow_db_supported)
			if (nvme_mdev_adm_needs_processing(ctx))
				break;

		/* process the submission queues*/
		sqid = 1;
		for_each_set_bit_from(sqid, vctrl->vsq_en, MAX_VIRTUAL_QUEUES)
			for (i = 0 ; i < ctx->arb_burst ; i++)
				if (!nvme_mdev_io_process_sq(ctx, sqid))
					break;

		/* process the completions from the guest*/
		cqid = 1;
		for_each_set_bit_from(cqid, vctrl->vcq_en, MAX_VIRTUAL_QUEUES)
			nvme_mdev_vcq_process(vctrl, cqid, true);

		/* IO schd */
		hsqcnt = nvme_mdev_vctrl_hqs_list(vctrl, hsqs);
		/* process the completions from the hardware*/
		for (i = 0 ; i < hsqcnt ; i++) {
			if (nvme_mdev_io_process_hwq(ctx, hsqs[i]) > 0)
				ctx->last_io_t = vctrl->now;
		}

		/* Check if we need to stop polling*/
		if (ctx->idle_timeout_ms) {
			if (timeout(ctx->last_io_t,
				    vctrl->now, ctx->idle_timeout_ms)) {
				idle = true;
				break;
			}
		}
		cond_resched();
	}

	/* Drain the host IO */
	for (;;) {
		/* IO schd */
		// hsqcnt = nvme_mdev_vctrl_hqs_list(vctrl, hsqs);

		bool pending_io = false;

		vctrl->now = ktime_get_coarse_boottime();

		if (nvme_mdev_vctrl_is_dead(vctrl) || ctx->hctrl->removing) {
			idle = false;
			break;
		}
		hsqcnt = nvme_mdev_vctrl_hqs_list(vctrl, hsqs);

		for (i = 0; i < hsqcnt; i++) {
			int n = nvme_mdev_io_process_hwq(ctx, hsqs[i]);

			if (n != -1)
				pending_io = true;
			if (n > 0)
				ctx->last_io_t = vctrl->now;
		}

		if (!pending_io)
			break;

		cond_resched();

		if (!timeout(ctx->last_io_t, vctrl->now, io_timeout_ms))
			continue;

		_WARN(ctx->vctrl, "IO: skipping flush - host IO timeout\n");
		idle = false;
		break;
	}

	/* Drain all the pending completion interrupts to the guest*/
	cqid = 1;
	for_each_set_bit_from(cqid, vctrl->vcq_en, MAX_VIRTUAL_QUEUES)
		if (nvme_mdev_vcq_flush(vctrl, cqid))
			idle = false;

	/* Park IO thread if IO is truly idle*/
	if (idle) {
		/* don't bother going idle if someone holds the vctrl
		 * lock. It might try to park us, and thus
		 * cause a deadlock
		 */
		if (!mutex_trylock(&vctrl->lock))
			return;

		sqid = 1;
		for_each_set_bit_from(sqid, vctrl->vsq_en, MAX_VIRTUAL_QUEUES)
			if (!nvme_mdev_vsq_suspend_io(vctrl, sqid)) {
				idle = false;
				break;
			}

		if (idle) {
			_DBG(ctx->vctrl, "IO: self-parking\n");
			vctrl->io_idle = true;
			nvme_mdev_io_pause(vctrl);
		}

		mutex_unlock(&vctrl->lock);
	}

	/* Admin poll for cases when shadow doorbell is not supported */
	if (!vctrl->mmio.shadow_db_supported) {
		if (mutex_trylock(&vctrl->lock)) {
			nvme_mdev_vcq_process(vctrl, 0, false);
			nvme_mdev_adm_process_sq(ctx->vctrl);
			ctx->last_admin_poll_time = vctrl->now;
			mutex_unlock(&ctx->vctrl->lock);
		}
	}
}

/* the main IO thread */
static int nvme_mdev_io_polling_thread(void *data)
{
	struct io_ctx ctx;

	if (kthread_should_stop())
		return 0;

	memset(&ctx, 0, sizeof(struct io_ctx));
	ctx.vctrl = (struct nvme_mdev_vctrl *)data;
	ctx.hctrl = ctx.vctrl->hctrl;
	nvme_mdev_udata_iter_setup(&ctx.vctrl->viommu, &ctx.udatait);

	_DBG(ctx.vctrl, "IO: iothread started\n");

	for (;;) {
		if (kthread_should_park()) {
			_DBG(ctx.vctrl, "IO: iothread parked\n");
			kthread_parkme();
		}

		if (kthread_should_stop())
			break;

		nvme_mdev_io_maintask(&ctx);
	}

	_DBG(ctx.vctrl, "IO: iothread stopped\n");
	return 0;
}

/* Kick the IO thread into running state*/
void nvme_mdev_io_resume(struct nvme_mdev_vctrl *vctrl)
{
	lockdep_assert_held(&vctrl->lock);

	if (!vctrl->iothread || !vctrl->iothread_parked)
		return;
	if (vctrl->io_idle || vctrl->vctrl_paused)
		return;

	vctrl->iothread_parked = false;
	/* has memory barrier*/
	kthread_unpark(vctrl->iothread);
}

/* Pause the IO thread */
void nvme_mdev_io_pause(struct nvme_mdev_vctrl *vctrl)
{
	lockdep_assert_held(&vctrl->lock);

	if (!vctrl->iothread || vctrl->iothread_parked)
		return;

	vctrl->iothread_parked = true;
	kthread_park(vctrl->iothread);
}

/* setup the main IO thread */
int nvme_mdev_io_create(struct nvme_mdev_vctrl *vctrl, unsigned int cpu)
{
	/*TODOLATER: IO: Better thread name*/
	char name[TASK_COMM_LEN];

	_DBG(vctrl, "IO: creating the polling iothread\n");

	if (WARN_ON(vctrl->iothread))
		return -EINVAL;

	snprintf(name, sizeof(name), "nvme%d_poll_io", vctrl->hctrl->id);

	vctrl->iothread_cpu = cpu;
	vctrl->iothread_parked = false;
	vctrl->io_idle = true;

	vctrl->iothread = kthread_create_on_node(nvme_mdev_io_polling_thread,
						 vctrl,
						 vctrl->hctrl->node,
						 name);
	if (IS_ERR(vctrl->iothread)) {
		vctrl->iothread = NULL;
		return PTR_ERR(vctrl->iothread);
	}

	kthread_bind(vctrl->iothread, cpu);

	if (vctrl->io_idle) {
		vctrl->iothread_parked = true;
		kthread_park(vctrl->iothread);
		return 0;
	}

	wake_up_process(vctrl->iothread);
	return 0;
}

/* End the  main IO thread */
void nvme_mdev_io_free(struct nvme_mdev_vctrl *vctrl)
{
	int ret;

	_DBG(vctrl, "IO: destroying the polling iothread\n");

	lockdep_assert_held(&vctrl->lock);
	nvme_mdev_io_pause(vctrl);
	ret = kthread_stop(vctrl->iothread);
	WARN_ON(ret);
	vctrl->iothread = NULL;
}

void nvme_mdev_assert_io_not_running(struct nvme_mdev_vctrl *vctrl)
{
	if (WARN_ON(vctrl->iothread && !vctrl->iothread_parked))
		nvme_mdev_io_pause(vctrl);
}
