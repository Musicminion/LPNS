// SPDX-License-Identifier: GPL-2.0+
/*
 * Virtual NVMe submission queue implementation
 * Copyright (c) 2019 - Maxim Levitsky
 */
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "priv.h"

#define DEBUG

/* Create new virtual completion queue */
int nvme_mdev_vsq_init(struct nvme_mdev_vctrl *vctrl,
		       u16 qid, dma_addr_t iova, bool cont, u16 size, u16 cqid)
{
	struct nvme_vsq *q = &vctrl->vsqs[qid];
	int ret;

	lockdep_assert_held(&vctrl->lock);

	/* IO schd */
	if (schd->cq_num >= MAX_ALL_VIRTUAL_QUEUES)
		return -1;
	mutex_init(&q->lock);

	q->iova = iova;
	q->cont = cont;
	q->qid = qid;
	q->size = size;
	q->head = 0;
	q->vcq = &vctrl->vcqs[cqid];
	q->data = NULL;
	q->hsq = 0;

	/* IO schd */
	q->tail = 0;
	q->vctrl_id = vctrl->id;
	q->vcq->vsq = q;

	ret = nvme_mdev_vsq_viommu_update(&vctrl->viommu, q);
	if (ret && (ret != -EFAULT))
		return ret;

	mutex_lock(&schd->lock);

	if (qid > 0) {
		ret = nvme_mdev_vctrl_hq_alloc(vctrl);
		if (ret < 0) {
			vunmap(q->data);
			mutex_unlock(&schd->lock);
			return ret;
		}
		q->hsq = ret;

		/* IO schd */
		if (ret == 0) {
			q->wait = true;
		}
		else {
			q->wait = false;
		}
	}
	mutex_unlock(&schd->lock);

	_DBG(vctrl, "VSQ: create qid=%d contig=%d, depth=%d cqid=%d hwqid=%d\n",
	     qid, cont, size, cqid, q->hsq);
	pr_info("VSQ: vctrl %d create qid=%d contig=%d, depth=%d cqid=%d hwqid=%d\n",
	     vctrl->id, qid, cont, size, cqid, q->hsq);

	set_bit(qid, vctrl->vsq_en);

	vctrl->mmio.dbs[q->qid].sqt = 0;
	vctrl->mmio.eidxs[q->qid].sqt = 0;

	return 0;
}

/* Update the kernel mapping of the queue */
int nvme_mdev_vsq_viommu_update(struct nvme_mdev_viommu *viommu,
				struct nvme_vsq *q)
{
	void *data;

	if (q->data)
		vunmap((void *)q->data);

	data = nvme_mdev_udata_queue_vmap(viommu, q->iova,
					  (unsigned int)q->size *
					  sizeof(struct nvme_command),
					  q->cont);

	q->data = IS_ERR(data) ? NULL : data;
	return IS_ERR(data) ? PTR_ERR(data) : 0;
}

/* Delete an virtual completion queue */
void nvme_mdev_vsq_delete(struct nvme_mdev_vctrl *vctrl, u16 qid)
{
	struct nvme_vsq *q = &vctrl->vsqs[qid];

	lockdep_assert_held(&vctrl->lock);
	_DBG(vctrl, "VSQ: delete qid=%d\n", q->qid);

	if (q->data)
		vunmap(q->data);
	q->data = NULL;

	mutex_lock(&schd->lock);
	if (q->hsq) {
		pr_info("VSQ: vctrl %d delete qid=%d, hwqid=%d\n", vctrl->id, q->qid, q->hsq);
		nvme_mdev_vctrl_hq_free(vctrl, q->hsq);
		q->hsq = 0;
	}
	mutex_unlock(&schd->lock);

	clear_bit(qid, vctrl->vsq_en);
}

/* Move queue head one item forward */
static void nvme_mdev_vsq_advance_head(struct nvme_vsq *q)
{
	q->head++;
	/* IO schd */
	if (q->head == q->size){
		q->head = 0;
	}
}

bool nvme_mdev_vsq_has_data(struct nvme_mdev_vctrl *vctrl,
			    struct nvme_vsq *q)
{
	u16 tail = le32_to_cpu(vctrl->mmio.dbs[q->qid].sqt);

	if (!vctrl->mmio.dbs || !vctrl->mmio.eidxs || !q->data)
		return false;

	if  (tail == q->head)
		return false;

	if (!nvme_mdev_mmio_db_check(vctrl, q->qid, q->size, tail))
		return false;
	return true;
}

/* get one command from a virtual submission queue */
const struct nvme_command *nvme_mdev_vsq_get_cmd(struct nvme_mdev_vctrl *vctrl,
						 struct nvme_vsq *q)
{
	u16 oldhead = q->head;
	u32 eidx;

	if (!nvme_mdev_vsq_has_data(vctrl, q))
		return NULL;
	if (!nvme_mdev_vcq_reserve_space(q->vcq))
		return NULL;
	nvme_mdev_vsq_advance_head(q);

	eidx = q->head + (q->size >> 1);
	if (eidx >= q->size)
		eidx -= q->size;

	vctrl->mmio.eidxs[q->qid].sqt = cpu_to_le32(eidx);

	return &q->data[oldhead];
}

bool nvme_mdev_vsq_suspend_io(struct nvme_mdev_vctrl *vctrl, u16 sqid)
{
	struct nvme_vsq *q = &vctrl->vsqs[sqid];
	u16 tail = le32_to_cpu(vctrl->mmio.dbs[q->qid].sqt);

	/* If the queue is not in working state don't allow the idle code
	 * to kick in
	 */
	if (!vctrl->mmio.dbs || !vctrl->mmio.eidxs || !q->data)
		return false;

	/* queue has data - refuse idle*/
	if (tail != q->head)
		return false;

	/* Write eventid to tell the user to ring normal doorbell*/
	vctrl->mmio.eidxs[q->qid].sqt = cpu_to_le32(q->head);

	/* memory barrier to ensure that the user have seen the eidx */
	mb();

	/* Check that doorbell diddn't move meanwhile */
	tail = le32_to_cpu(vctrl->mmio.dbs[q->qid].sqt);
	return (tail == q->head);
}

/* complete a command (IO version)*/
void nvme_mdev_vsq_cmd_done_io(struct nvme_mdev_vctrl *vctrl,
			       u16 sqid, u16 cid, u16 status)
{
	struct nvme_vsq *q = &vctrl->vsqs[sqid];

	nvme_mdev_vcq_write_io(vctrl, q->vcq, q->head, q->qid, cid, status);
}

/* complete a command (ADMIN version)*/
void nvme_mdev_vsq_cmd_done_adm(struct nvme_mdev_vctrl *vctrl,
				u32 dw0, u16 cid, u16 status)
{
	struct nvme_vsq *q = &vctrl->vsqs[0];

	nvme_mdev_vcq_write_adm(vctrl, q->vcq, dw0, q->head, cid, status);
}
