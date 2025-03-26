// SPDX-License-Identifier: GPL-2.0+
/*
 * NVMe admin command implementation
 * Copyright (c) 2019 - Maxim Levitsky
 */
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "priv.h"
#define DEBUG

struct adm_ctx {
	struct nvme_mdev_vctrl *vctrl;
	struct nvme_mdev_hctrl *hctrl;
	const struct nvme_command *in;
	struct nvme_mdev_vns *ns;
	struct nvme_ext_data_iter udatait;
	unsigned int datalen;
};

/*Identify Controller */
static int nvme_mdev_adm_handle_id_cntrl(struct adm_ctx *ctx)
{
	int ret;
	const struct nvme_identify *in = &ctx->in->identify;
	struct nvme_id_ctrl *id;
	char mn[50];

	if (in->nsid != 0)
		return DNR(NVME_SC_INVALID_FIELD);

	id =  kzalloc(sizeof(*id), GFP_KERNEL);
	if (!id)
		return NVME_SC_INTERNAL;

	sprintf(mn, "NVMe MDEV virtual device - %s", get_qos_type(ctx->vctrl->type));

	/** Controller Capabilities and Features ************************/
	// PCI vendor ID
	store_le16(&id->vid, NVME_MDEV_PCI_VENDOR_ID);
	// PCI Subsystem Vendor ID
	store_le16(&id->ssvid, NVME_MDEV_PCI_SUBVENDOR_ID);
	// Serial Number
	store_strsp(id->sn, ctx->vctrl->serial);
	// Model Number
	// store_strsp(id->mn, "NVMe MDEV virtual device");
	store_strsp(id->mn, mn);
	// Firmware Revision
	store_strsp(id->fr, NVME_MDEV_FIRMWARE_VERSION);
	// Recommended Arbitration Burst
	id->rab = 6;
	// IEEE OUI Identifier for the controller vendor
	id->ieee[0] = 0;
	// Controller Multi-Path I/O and Namespace Sharing Capabilities
	id->cmic = 0;
	// Maximum Data Transfer Size (power of two, in page size units)
	id->mdts = ctx->hctrl->mdts;
	// controller ID
	id->cntlid = 0;
	// NVME supported version
	store_le32(&id->ver, NVME_MDEV_NVME_VER);
	// RTD3 Resume Latency
	id->rtd3r = 0;
	//RTD3 Entry Latency
	id->rtd3e = 0;
	// Optional Asynchronous Events Supported
	store_le32(&id->oaes, NVME_AEN_CFG_NS_ATTR);
	// Controller Attributes (misc junk)
	id->ctratt = 0;

	/*Admin Command Set Attributes & Optional Controller Capabilities */
	// Optional Admin Command Support
	id->oacs = ctx->vctrl->mmio.shadow_db_supported ?
			NVME_CTRL_OACS_DBBUF_SUPP : 0;
	// Abort Command Limit (dummy, zero based)
	id->acl = 3;
	 // Asynchronous Event Request Limit (zero based)
	id->aerl = MAX_AER_COMMANDS - 1;
	// Firmware Updates (dummy)
	id->frmw = 3;
	// Log Page Attributes
	// (IMPLEMENT: bit for commands supported and effects)
	id->lpa = 0;
	// Error Log Page Entries
	// (zero based, IMPLEMENT: dummy for now)
	id->elpe = 0;
	// Number of Power States Support
	// (zero based, IMPLEMENT: dummy for now)
	id->npss = 0;
	// Admin Vendor Specific Command Configuration (junk)
	id->avscc = 0;
	// Autonomous Power State Transition Attributes
	id->apsta = 0;
	// Warning Composite Temperature Threshold (dummy)
	id->wctemp = 0x157;
	// Critical Composite Temperature Threshold (dummy)
	id->cctemp = 0x175;
	// Maximum Time for Firmware Activation (dummy)
	id->mtfa = 0;
	// Host Memory Buffer Preferred Size (dummy)
	id->hmpre = 0;
	// Host Memory Buffer Minimum Size (dummy)
	id->hmmin = 0;
	// Total NVM Capacity (not supported)
	id->tnvmcap[0] = 0;
	// Unallocated NVM Capacity (not supported for now)
	id->unvmcap[0] = 0;
	// Replay Protected Memory Block Support
	id->rpmbs = 0;
	// Extended Device Self-test Time (dummy)
	id->edstt = 0;
	// Device Self-test Options (dummy)
	id->dsto = 0;
	// Firmware Update Granularity (dummy)
	id->fwug = 0;
	// Keep Alive Support (not supported)
	id->kas = 0;
	// Host Controlled Thermal Management Attributes (not supported)
	id->hctma = 0;
	// Minimum Thermal Management Temperature (not supported)
	id->mntmt = 0;
	// Maximum Thermal Management Temperature (not supported)
	id->mxtmt = 0;
	// Sanitize capabilities (not supported)
	id->sanicap = 0;

	/****************** NVM Command Set Attributes ********************/
	// Submission Queue Entry Size
	id->sqes = (0x6 << 4) | 0x6;
	// Completion Queue Entry Size
	id->cqes = (0x4 << 4) | 0x4;
	// Maximum Outstanding Commands
	id->maxcmd = 0;
	// Number of Namespaces
	id->nn = MAX_VIRTUAL_NAMESPACES;
	// Optional NVM Command Support
	// (we add dsm and write zeros if host supports them)
	id->oncs = ctx->hctrl->oncs;
	// TODOLATER: IO: Fused Operation Support
	id->fuses = 0;
	// Format NVM Attributes (don't support)
	id->fna = 0;
	// Volatile Write Cache (tell that always exist)
	id->vwc = 1;
	// Atomic Write Unit Normal (zero based value in blocks)
	id->awun = 0;
	// Atomic Write Unit Power Fail (ditto)
	id->awupf = 0;
	// NVM Vendor Specific Command Configuration
	id->nvscc = 0;
	// Atomic Compare & Write Unit  (zero based value in blocks)
	id->acwu = 0;
	// SGL Support
	id->sgls = 0;
	// NVM Subsystem NVMe Qualified Name
	strncpy(id->subnqn, ctx->vctrl->subnqn, sizeof(id->subnqn));

	/******************Power state descriptors ***********************/
	store_le16(&id->psd[0].max_power, 0x9c4); // dummy
	store_le32(&id->psd[0].entry_lat, 0x10);
	store_le32(&id->psd[0].exit_lat, 0x4);

	ret = nvme_mdev_write_to_udata(&ctx->udatait, id, sizeof(*id));
	kfree(id);
	return nvme_mdev_translate_error(ret);
}

/*Identify Namespace data structure for the specified NSID or common one */
static int nvme_mdev_adm_handle_id_ns(struct adm_ctx *ctx)
{
	int ret;
	struct nvme_id_ns *idns;
	u32 nsid = le32_to_cpu(ctx->in->identify.nsid);

	if (nsid == 0xffffffff || nsid == 0 || nsid > MAX_VIRTUAL_NAMESPACES)
		return DNR(NVME_SC_INVALID_NS);

	/* Allocate return structure*/
	idns =  kzalloc(NVME_IDENTIFY_DATA_SIZE, GFP_KERNEL);
	if (!idns)
		return NVME_SC_INTERNAL;

	if (ctx->ns) {
		//Namespace Size
		store_le64(&idns->nsze, ctx->ns->ns_size);
		// Namespace Capacity
		store_le64(&idns->ncap, ctx->ns->ns_size);
		// Namespace Utilization
		store_le64(&idns->nuse, ctx->ns->ns_size);
		// Namespace Features (nothing to set here yet)
		idns->nsfeat = 0;
		// Number of LBA Formats (dummy, zero based)
		idns->nlbaf = 0;
		// Formatted LBA Size (current LBA format in use)
		// + external metadata bit
		idns->flbas = 0;
		// Metadata Capabilities
		idns->mc = 0;
		// End-to-end Data Protection Capabilities
		idns->dpc = 0;
		// End-to-end Data Protection Type Settings
		idns->dps = 0;
		// Namespace Multi-path I/O and Namespace Sharing Capabilities
		idns->nmic = 0;
		// Reservation Capabilities
		idns->rescap = 0;
		// Format Progress Indicator (dummy)
		idns->fpi = 0;
		// Namespace Atomic Write Unit Normal
		idns->nawun = 0;
		// Namespace Atomic Write Unit Power Fail
		idns->nawupf = 0;
		// Namespace Atomic Compare & Write Unit
		idns->nacwu = 0;
		// Namespace Atomic Boundary Size Normal
		idns->nabsn = 0;
		// Namespace Atomic Boundary Offset
		idns->nabo = 0;
		// Namespace Atomic Boundary Size Power Fail
		idns->nabspf = 0;
		// Namespace Optimal IO Boundary
		idns->noiob = ctx->ns->noiob;
		// NVM Capacity (another capacity but in bytes)
		idns->nvmcap[0]  = 0;

		// TODOLATER: NS: support NGUID/EUI64
		idns->nguid[0] = 0;
		idns->eui64[0] = 0;
		// format 0 metadata size
		idns->lbaf[0].ms = 0;
		// format 0 block size (in power of two)
		idns->lbaf[0].ds = ctx->ns->blksize_shift;
		// format 0 relative performance
		idns->lbaf[0].rp = 0;
	}

	ret = nvme_mdev_write_to_udata(&ctx->udatait, idns,
				       NVME_IDENTIFY_DATA_SIZE);
	kfree(idns);
	return nvme_mdev_translate_error(ret);
}

/* Namespace Identification Descriptor list for the specified NSID.*/
static int nvme_mdev_adm_handle_id_ns_desc(struct adm_ctx *ctx)
{
	struct ns_desc {
		struct nvme_ns_id_desc uuid_desc;
		uuid_t uuid;
		struct nvme_ns_id_desc null_desc;
	};

	int ret;
	struct ns_desc *id;

	if (!ctx->ns)
		return DNR(NVME_SC_INVALID_NS);

	/* Allocate return structure */
	id = kzalloc(NVME_IDENTIFY_DATA_SIZE, GFP_KERNEL);
	if (!id)
		return NVME_SC_INTERNAL;

	id->uuid_desc.nidt = NVME_NIDT_UUID;
	id->uuid_desc.nidl = NVME_NIDT_UUID_LEN;
	memcpy(&id->uuid, &ctx->ns->uuid, sizeof(id->uuid));

	ret = nvme_mdev_write_to_udata(&ctx->udatait, id,
				       NVME_IDENTIFY_DATA_SIZE);
	kfree(id);
	return nvme_mdev_translate_error(ret);
}

/*Active Namespace ID list */
static int nvme_mdev_adm_handle_id_active_ns_list(struct adm_ctx *ctx)
{
	u32 nsid, start_nsid = le32_to_cpu(ctx->in->identify.nsid);
	struct nvme_mdev_vctrl *vctrl = ctx->vctrl;
	int i = 0, ret;

	__le32 *nslist = kzalloc(NVME_IDENTIFY_DATA_SIZE, GFP_KERNEL);

	if (start_nsid >= 0xfffffffe)
		return DNR(NVME_SC_INVALID_NS);

	for (nsid = start_nsid + 1; nsid <= MAX_VIRTUAL_NAMESPACES; nsid++)
		if (nvme_mdev_vns_from_vnsid(vctrl, nsid))
			nslist[i++] = nsid;

	ret = nvme_mdev_write_to_udata(&ctx->udatait, nslist,
				       NVME_IDENTIFY_DATA_SIZE);
	kfree(nslist);
	return nvme_mdev_translate_error(ret);
}

/* Handle Identify command*/
static int nvme_mdev_adm_handle_id(struct adm_ctx *ctx)
{
	const struct nvme_identify *in = &ctx->in->identify;

	int ret = nvme_mdev_udata_iter_set_dptr(&ctx->udatait,
						&ctx->in->common.dptr,
						NVME_IDENTIFY_DATA_SIZE);

	u32 nsid = le32_to_cpu(in->nsid);

	if (ret)
		return nvme_mdev_translate_error(ret);

	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_DW23 | RSRV_MPTR | RSRV_DW11_15))
		return DNR(NVME_SC_INVALID_FIELD);

	if (in->ctrlid)
		return DNR(NVME_SC_INVALID_FIELD);

	ctx->ns = nvme_mdev_vns_from_vnsid(ctx->vctrl, nsid);

	switch (ctx->in->identify.cns) {
	case NVME_ID_CNS_CTRL:
		_DBG(ctx->vctrl, "ADMINQ: IDENTIFY CTRL\n");
		return nvme_mdev_adm_handle_id_cntrl(ctx);
	case NVME_ID_CNS_NS_ACTIVE_LIST:
		_DBG(ctx->vctrl, "ADMINQ: IDENTIFY ACTIVE_NS_LIST\n");
		return nvme_mdev_adm_handle_id_active_ns_list(ctx);
	case NVME_ID_CNS_NS:
		_DBG(ctx->vctrl, "ADMINQ: IDENTIFY NS=0x%08x\n", nsid);
		return nvme_mdev_adm_handle_id_ns(ctx);
	case NVME_ID_CNS_NS_DESC_LIST:
		_DBG(ctx->vctrl, "ADMINQ: IDENTIFY NS_DESC NS=0x%08x\n", nsid);
		return nvme_mdev_adm_handle_id_ns_desc(ctx);
	default:
		return DNR(NVME_SC_INVALID_FIELD);
	}
}

/* Error log for AER */
static int nvme_mdev_adm_handle_get_log_page_err(struct adm_ctx *ctx)
{
	struct nvme_err_log_entry dummy_entry;
	int ret;

	// write one dummy entry with 0 error count
	memset(&dummy_entry, 0, sizeof(dummy_entry));

	ret = nvme_mdev_write_to_udata(&ctx->udatait,
				       &dummy_entry,
				       min((unsigned int)sizeof(dummy_entry),
					   ctx->datalen));

	return nvme_mdev_translate_error(ret);
}

/* This log page allows to tell user about connected/disconnected namespaces */
static int nvme_mdev_adm_handle_get_log_page_changed_ns(struct adm_ctx *ctx)
{
	unsigned int datasize = min(ctx->vctrl->ns_log_size * 4, ctx->datalen);

	int ret = nvme_mdev_write_to_udata(&ctx->udatait,
					   &ctx->vctrl->ns_log, datasize);

	nvme_mdev_vns_log_reset(ctx->vctrl);
	return nvme_mdev_translate_error(ret);
}

/* S.M.A.R.T. log*/
static int nvme_mdev_adm_handle_get_log_page_smart(struct adm_ctx *ctx)
{
	unsigned int datasize = min_t(unsigned int,
			sizeof(struct nvme_smart_log), ctx->datalen);
	int ret;
	struct nvme_smart_log *log = kzalloc(sizeof(*log), GFP_KERNEL);

	if (!log)
		return NVME_SC_INTERNAL;

	/* Some dummy values */
	log->avail_spare = 100;
	log->spare_thresh = 10;
	store_le16(&log->temperature, 0x140);

	ret = nvme_mdev_write_to_udata(&ctx->udatait, log, datasize);
	kfree(log);
	return nvme_mdev_translate_error(ret);
}

/* FW slot log - useless */
static int nvme_mdev_adm_handle_get_log_page_fw_slot(struct adm_ctx *ctx)
{
	unsigned int datasize = min_t(unsigned int,
				      sizeof(struct nvme_fw_slot_info_log),
				      ctx->datalen);
	int ret;
	struct nvme_fw_slot_info_log *log = kzalloc(sizeof(*log), GFP_KERNEL);

	if (!log)
		return NVME_SC_INTERNAL;

	ret = nvme_mdev_write_to_udata(&ctx->udatait, log, datasize);
	kfree(log);
	return nvme_mdev_translate_error(ret);
}

/* Response to GET LOG PAGE command */
static int nvme_mdev_adm_handle_get_log_page(struct adm_ctx *ctx)
{
	const struct nvme_get_log_page_command *in = &ctx->in->get_log_page;
	u8 log_page_id = ctx->in->get_log_page.lid;
	int ret;

	ctx->datalen = (le16_to_cpu(in->numdl) + 1) * 4;

	/*  We don't support extensions (NUMDU,LPOL,LPOU) */
	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_DW23 | RSRV_MPTR | RSRV_DW11_15))
		return DNR(NVME_SC_INVALID_FIELD);

	/* Currently ignore the NSID in the command */

	/* ACK the AER */
	if ((in->lsp & 0x80) == 0)
		nvme_mdev_event_process_ack(ctx->vctrl, log_page_id);

	/* map data pointer */
	ret = nvme_mdev_udata_iter_set_dptr(&ctx->udatait,
					    &in->dptr, ctx->datalen);
	if (ret)
		return nvme_mdev_translate_error(ret);

	switch (log_page_id) {
	case NVME_LOG_ERROR:
		_DBG(ctx->vctrl, "ADMINQ: GET_LOG_PAGE : ERRLOG\n");
		return nvme_mdev_adm_handle_get_log_page_err(ctx);
	case NVME_LOG_CHANGED_NS:
		_DBG(ctx->vctrl, "ADMINQ: GET_LOG_PAGE : CHANGED_NS\n");
		return nvme_mdev_adm_handle_get_log_page_changed_ns(ctx);
	case NVME_LOG_SMART:
		_DBG(ctx->vctrl, "ADMINQ: GET_LOG_PAGE : SMART\n");
		return nvme_mdev_adm_handle_get_log_page_smart(ctx);
	case NVME_LOG_FW_SLOT:
		_DBG(ctx->vctrl, "ADMINQ: GET_LOG_PAGE : FWSLOT\n");
		return nvme_mdev_adm_handle_get_log_page_fw_slot(ctx);
	default:
		_DBG(ctx->vctrl, "ADMINQ: GET_LOG_PAGE : log page 0x%02x\n",
		     log_page_id);
		return DNR(NVME_SC_INVALID_FIELD);
	}
}

/* Response to CREATE CQ command */
static int nvme_mdev_adm_handle_create_cq(struct adm_ctx *ctx)
{
	int irq = -1, ret;
	struct nvme_mdev_vctrl *vctrl = ctx->vctrl;
	const struct nvme_create_cq *in = &ctx->in->create_cq;
	u16 cqid = le16_to_cpu(in->cqid);
	u16 qsize = le16_to_cpu(in->qsize);
	u16 cq_flags = le16_to_cpu(in->cq_flags);

	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_NSID | RSRV_DW23 | RSRV_DPTR_PRP2 |
				   RSRV_MPTR | RSRV_DW12_15))
		return DNR(NVME_SC_INVALID_FIELD);

	/* QID checks*/
	if (!cqid ||
	    cqid >= MAX_VIRTUAL_QUEUES || test_bit(cqid, vctrl->vcq_en))
		return DNR(NVME_SC_QID_INVALID);

	/* Queue size checks*/
	if (qsize > (MAX_VIRTUAL_QUEUE_DEPTH - 1) || qsize < 1)
		return DNR(NVME_SC_QUEUE_SIZE);

	/* Queue flags checks */
	if (cq_flags & ~(NVME_QUEUE_PHYS_CONTIG | NVME_CQ_IRQ_ENABLED))
		return DNR(NVME_SC_INVALID_FIELD);

	if (cq_flags & NVME_CQ_IRQ_ENABLED) {
		irq = le16_to_cpu(in->irq_vector);
		if (irq >= MAX_VIRTUAL_IRQS)
			return DNR(NVME_SC_INVALID_VECTOR);
	}

	ret = nvme_mdev_vcq_init(ctx->vctrl, cqid,
				 le64_to_cpu(in->prp1),
				 cq_flags & NVME_QUEUE_PHYS_CONTIG,
				 qsize + 1, irq);

	return nvme_mdev_translate_error(ret);
}

/* Response to DELETE CQ command */
static int nvme_mdev_adm_handle_delete_cq(struct adm_ctx *ctx)
{
	struct nvme_mdev_vctrl *vctrl = ctx->vctrl;
	const struct nvme_delete_queue *in =  &ctx->in->delete_queue;
	u16 qid = le16_to_cpu(in->qid), sqid;

	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_NSID | RSRV_DW23 | RSRV_DPTR |
				   RSRV_MPTR | RSRV_DW11_15))
		return DNR(NVME_SC_INVALID_FIELD);

	if (!qid || qid >= MAX_VIRTUAL_QUEUES || !test_bit(qid, vctrl->vcq_en))
		return DNR(NVME_SC_QID_INVALID);

	for_each_set_bit(sqid, vctrl->vsq_en, MAX_VIRTUAL_QUEUES)
		if (vctrl->vsqs[sqid].vcq == &vctrl->vcqs[qid])
			return DNR(NVME_SC_INVALID_QUEUE);

	nvme_mdev_vcq_delete(vctrl, qid);
	return NVME_SC_SUCCESS;
}

/* Response to CREATE SQ command */
static int nvme_mdev_adm_handle_create_sq(struct adm_ctx *ctx)
{
	const struct nvme_create_sq *in = &ctx->in->create_sq;
	struct nvme_mdev_vctrl *vctrl = ctx->vctrl;
	int ret;

	u16 sqid = le16_to_cpu(in->sqid);
	u16 cqid = le16_to_cpu(in->cqid);
	u16 qsize = le16_to_cpu(in->qsize);
	u16 sq_flags = le16_to_cpu(in->sq_flags);

	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_NSID | RSRV_DW23 | RSRV_DPTR_PRP2 |
				   RSRV_MPTR | RSRV_DW12_15))
		return DNR(NVME_SC_INVALID_FIELD);

	if (!sqid ||
	    sqid >= MAX_VIRTUAL_QUEUES || test_bit(sqid, vctrl->vsq_en))
		return DNR(NVME_SC_QID_INVALID);

	if (!cqid || cqid  >= MAX_VIRTUAL_QUEUES)
		return DNR(NVME_SC_QID_INVALID);

	if (!test_bit(cqid, vctrl->vcq_en))
		return DNR(NVME_SC_CQ_INVALID);

	/* Queue size checks */
	if (qsize > (MAX_VIRTUAL_QUEUE_DEPTH - 1) || qsize < 1)
		return DNR(NVME_SC_QUEUE_SIZE);

	/* Queue flags checks */
	if (sq_flags & ~(NVME_QUEUE_PHYS_CONTIG | NVME_SQ_PRIO_MASK))
		return DNR(NVME_SC_INVALID_FIELD);

	ret = nvme_mdev_vsq_init(ctx->vctrl, sqid,
				 le64_to_cpu(in->prp1),
				 sq_flags & NVME_QUEUE_PHYS_CONTIG,
				 qsize + 1, cqid);
	if (ret)
		goto error;

	return NVME_SC_SUCCESS;
error:
	return nvme_mdev_translate_error(ret);
}

/* Response to DELETE SQ command */
static int nvme_mdev_adm_handle_delete_sq(struct adm_ctx *ctx)
{
	struct nvme_mdev_vctrl *vctrl = ctx->vctrl;
	const struct nvme_delete_queue *in =  &ctx->in->delete_queue;
	u16 qid = le16_to_cpu(in->qid);

	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_NSID | RSRV_DW23 | RSRV_DPTR |
				   RSRV_MPTR | RSRV_DW11_15))
		return DNR(NVME_SC_INVALID_FIELD);

	if (!qid || qid >= MAX_VIRTUAL_QUEUES || !test_bit(qid, vctrl->vsq_en))
		return DNR(NVME_SC_QID_INVALID);

	nvme_mdev_vsq_delete(ctx->vctrl, qid);
	return NVME_SC_SUCCESS;
}

/* Set the shadow doorbell */
static int nvme_mdev_adm_handle_dbbuf(struct adm_ctx *ctx)
{
	const struct nvme_dbbuf *in = &ctx->in->dbbuf;
	int ret;

	dma_addr_t sdb_iova = le64_to_cpu(in->prp1);
	dma_addr_t eidx_iova = le64_to_cpu(in->prp2);

	/* Check if we support the shadow doorbell */
	if (!ctx->vctrl->mmio.shadow_db_supported)
		return DNR(NVME_SC_INVALID_OPCODE);

	/* Don't allow to enable the shadow doorbell more that once */
	if (ctx->vctrl->mmio.shadow_db_en)
		return DNR(NVME_SC_INVALID_FIELD);

	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_NSID | RSRV_DW23 |
				   RSRV_MPTR | RSRV_DW10_15))
		return DNR(NVME_SC_INVALID_FIELD);

	/* check input buffers */
	if ((OFFSET_IN_PAGE(sdb_iova) != 0) || (OFFSET_IN_PAGE(eidx_iova) != 0))
		return DNR(NVME_SC_INVALID_FIELD);

	/* switch to the new doorbell buffer */
	ret = nvme_mdev_mmio_enable_dbs_shadow(ctx->vctrl, sdb_iova, eidx_iova);
	return nvme_mdev_translate_error(ret);
}

/* Response to GET_FEATURES command */
static int nvme_mdev_adm_handle_get_features(struct adm_ctx *ctx)
{
	u32 value = 0;
	u32 irq;
	const struct nvme_features *in = &ctx->in->features;
	struct nvme_mdev_vctrl *vctrl = ctx->vctrl;
	unsigned int tmp;

	u32 fid = le32_to_cpu(in->fid);
	u16 cid = le16_to_cpu(in->command_id);

	_DBG(ctx->vctrl, "ADMINQ: GET_FEATURES FID=0x%x\n", fid);

	/* common reserved bits*/
	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_DW23 | RSRV_DPTR |
				   RSRV_MPTR | RSRV_DW12_15))
		return DNR(NVME_SC_INVALID_FIELD);

	/* reserved bits in dword10*/
	if (fid > 0xFF)
		return DNR(NVME_SC_INVALID_FIELD);

	/* reserved bits in dword11*/
	if (fid != NVME_FEAT_IRQ_CONFIG && in->dword11 != 0)
		return DNR(NVME_SC_INVALID_FIELD);

	switch (fid) {
	/* Number of queues */
	case NVME_FEAT_NUM_QUEUES:
		value = (MAX_VIRTUAL_QUEUES - 1) |
			((MAX_VIRTUAL_QUEUES - 1) << 16);
		goto out;

	/* Arbitration */
	case NVME_FEAT_ARBITRATION:
		value = vctrl->arb_burst_shift & 0x7;
		goto out;

	/* Interrupt coalescing settings*/
	case NVME_FEAT_IRQ_COALESCE:
		tmp = vctrl->irqs.irq_coalesc_time_us;
		do_div(tmp, 100);
		value = (vctrl->irqs.irq_coalesc_max - 1) | (tmp << 8);
		goto out;

	/* Interrupt coalescing disable for a specific interrupt */
	case NVME_FEAT_IRQ_CONFIG:
		irq = le32_to_cpu(in->dword11);
		if (irq >= MAX_VIRTUAL_IRQS)
			return DNR(NVME_SC_INVALID_FIELD);

		value = irq;
		if (vctrl->irqs.vecs[irq].irq_coalesc_en)
			value |= (1 << 16);
		goto out;

	/* Volatile write cache */
	case NVME_FEAT_VOLATILE_WC:
		/*we always report write cache due to mediation*/
		value = 0x1;
		goto out;

	/* Limited error recovery */
	case NVME_FEAT_ERR_RECOVERY:
		value = 0;
		break;

	/* Workload hint + power state */
	case NVME_FEAT_POWER_MGMT:
		value = vctrl->worload_hint << 4;
		break;

	/* Temperature threshold */
	case NVME_FEAT_TEMP_THRESH:
		return DNR(NVME_SC_INVALID_FIELD);

	/* AEN permanent masking*/
	case NVME_FEAT_ASYNC_EVENT:
		value = nvme_mdev_event_read_aen_config(vctrl);
		goto out;
	default:
		return DNR(NVME_SC_INVALID_FIELD);
	}
out:
	nvme_mdev_vsq_cmd_done_adm(ctx->vctrl, value, cid, NVME_SC_SUCCESS);
	return -1;
}

/* Response to SET_FEATURES command */
static int nvme_mdev_adm_handle_set_features(struct adm_ctx *ctx)
{
	const struct nvme_features *in = &ctx->in->features;
	struct nvme_mdev_vctrl *vctrl = ctx->vctrl;

	u32 value = le32_to_cpu(in->dword11);
	u8 fid = le32_to_cpu(in->fid) & 0xFF;
	u16 cid = le16_to_cpu(in->command_id);
	u32 nsid = le32_to_cpu(in->nsid);

	_DBG(ctx->vctrl, "ADMINQ: SET_FEATURES cmd. FID=0x%x\n", fid);

	if (nsid != 0xffffffff && nsid != 0)
		return DNR(NVME_SC_FEATURE_NOT_PER_NS);

	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_DW23 | RSRV_DPTR |
				   RSRV_MPTR | RSRV_DW12_15))
		return DNR(NVME_SC_INVALID_FIELD);

	switch (fid) {
	case NVME_FEAT_NUM_QUEUES:
		/* need to return the value here as well */
		value = (MAX_VIRTUAL_QUEUES - 1) |
			((MAX_VIRTUAL_QUEUES - 1) << 16);

		nvme_mdev_vsq_cmd_done_adm(ctx->vctrl, value,
					   cid, NVME_SC_SUCCESS);
		return -1;

	case NVME_FEAT_ARBITRATION:
		vctrl->arb_burst_shift = value & 0x7;
		return NVME_SC_SUCCESS;

	case NVME_FEAT_IRQ_COALESCE:
		vctrl->irqs.irq_coalesc_max = (value & 0xFF) + 1;
		vctrl->irqs.irq_coalesc_time_us = ((value >> 8) & 0xFF) * 100;
		return NVME_SC_SUCCESS;

	case NVME_FEAT_IRQ_CONFIG: {
		u16 irq = value & 0xFFFF;

		if (irq >= MAX_VIRTUAL_IRQS)
			return DNR(NVME_SC_INVALID_FIELD);

		vctrl->irqs.vecs[irq].irq_coalesc_en = (value & 0x10000) != 0;
		return NVME_SC_SUCCESS;
	}
	case NVME_FEAT_VOLATILE_WC:
		return (value != 0x1) ? DNR(NVME_SC_FEATURE_NOT_CHANGEABLE) :
							NVME_SC_SUCCESS;

	case NVME_FEAT_ERR_RECOVERY:
		return (value != 0) ? DNR(NVME_SC_FEATURE_NOT_CHANGEABLE) :
							NVME_SC_SUCCESS;
	case NVME_FEAT_POWER_MGMT:
		if (value & 0xFFFFFF0F)
			return DNR(NVME_SC_INVALID_FIELD);
		vctrl->worload_hint = value >> 4;
		return NVME_SC_SUCCESS;

	case NVME_FEAT_TEMP_THRESH:
		return DNR(NVME_SC_INVALID_FIELD);

	case NVME_FEAT_ASYNC_EVENT:
		nvme_mdev_event_set_aen_config(vctrl, value);
		return NVME_SC_SUCCESS;
	default:
		return DNR(NVME_SC_INVALID_FIELD);
	}
}

/* Response to AER command */
static int nvme_mdev_adm_handle_async_event(struct adm_ctx *ctx)
{
	u16 cid = le16_to_cpu(ctx->in->common.command_id);

	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_NSID | RSRV_DW23 | RSRV_DPTR |
				   RSRV_MPTR | RSRV_DW10_15))
		return DNR(NVME_SC_INVALID_FIELD);

	return nvme_mdev_event_request_receive(ctx->vctrl, cid);
}

/* (Dummy) response to ABORT command*/
static int nvme_mdev_adm_handle_abort(struct adm_ctx *ctx)
{
	if (!check_reserved_dwords(ctx->in->dwords, 16,
				   RSRV_NSID | RSRV_DW23 | RSRV_DPTR |
				   RSRV_MPTR | RSRV_DW10_15))
		return DNR(NVME_SC_INVALID_FIELD);

	return DNR(NVME_SC_ABORT_MISSING);
}

/* Process one new command in the admin queue*/
static int nvme_mdev_adm_handle_cmd(struct adm_ctx *ctx)
{
	u8 optcode = ctx->in->common.opcode;

	ctx->ns = NULL;
	ctx->datalen = 0;

	if (ctx->in->common.flags != 0)
		return DNR(NVME_SC_INVALID_FIELD);

	switch (optcode) {
	case nvme_admin_identify:
		return nvme_mdev_adm_handle_id(ctx);
	case nvme_admin_create_cq:
		_DBG(ctx->vctrl, "ADMINQ: CREATE_CQ\n");
		return nvme_mdev_adm_handle_create_cq(ctx);
	case nvme_admin_create_sq:
		_DBG(ctx->vctrl, "ADMINQ: CREATE_SQ\n");
		return nvme_mdev_adm_handle_create_sq(ctx);
	case nvme_admin_delete_sq:
		_DBG(ctx->vctrl, "ADMINQ: DELETE_SQ\n");
		return nvme_mdev_adm_handle_delete_sq(ctx);
	case nvme_admin_delete_cq:
		_DBG(ctx->vctrl, "ADMINQ: DELETE_CQ\n");
		return nvme_mdev_adm_handle_delete_cq(ctx);
	case nvme_admin_dbbuf:
		_DBG(ctx->vctrl, "ADMINQ: DBBUF_CONFIG\n");
		return nvme_mdev_adm_handle_dbbuf(ctx);
	case nvme_admin_get_log_page:
		return nvme_mdev_adm_handle_get_log_page(ctx);
	case nvme_admin_get_features:
		return nvme_mdev_adm_handle_get_features(ctx);
	case nvme_admin_set_features:
		return nvme_mdev_adm_handle_set_features(ctx);
	case nvme_admin_async_event:
		_DBG(ctx->vctrl, "ADMINQ: ASYNC_EVENT_REQ\n");
		return nvme_mdev_adm_handle_async_event(ctx);
	case nvme_admin_abort_cmd:
		_DBG(ctx->vctrl, "ADMINQ: ABORT\n");
		return nvme_mdev_adm_handle_abort(ctx);
	default:
		_DBG(ctx->vctrl, "ADMINQ: optcode 0x%04x\n", optcode);
		return DNR(NVME_SC_INVALID_OPCODE);
	}
}

/* Process all pending admin commands */
void nvme_mdev_adm_process_sq(struct nvme_mdev_vctrl *vctrl)
{
	struct adm_ctx ctx;

	lockdep_assert_held(&vctrl->lock);
	memset(&ctx, 0, sizeof(struct adm_ctx));
	ctx.vctrl = vctrl;
	ctx.hctrl = vctrl->hctrl;
	nvme_mdev_udata_iter_setup(&vctrl->viommu, &ctx.udatait);

	nvme_mdev_io_pause(ctx.vctrl);

	while (!(nvme_mdev_vctrl_is_dead(vctrl))) {
		int ret;
		u16 cid;

		ctx.in = nvme_mdev_vsq_get_cmd(vctrl, &vctrl->vsqs[0]);
		if (!ctx.in)
			break;

		cid = le16_to_cpu(ctx.in->common.command_id);
		ret = nvme_mdev_adm_handle_cmd(&ctx);

		if (ret == -1)
			continue;

		if (ret != 0)
			_DBG(vctrl, "ADMINQ: CID 0x%x FAILED: status 0x%x\n",
			     cid, ret);
		nvme_mdev_vsq_cmd_done_adm(vctrl, 0, cid, ret);
	}

	/* IO schd */
	nvme_mdev_io_resume(ctx.vctrl);
}
