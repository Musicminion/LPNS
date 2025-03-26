// SPDX-License-Identifier: GPL-2.0+
/*
 * Virtual NVMe controller implementation
 * Copyright (c) 2019 - Maxim Levitsky
 */
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/mdev.h>
#include <linux/nvme.h>
#include "priv.h"

// #define DEBUG 1

bool nvme_mdev_vctrl_is_dead(struct nvme_mdev_vctrl *vctrl)
{
	return (vctrl->mmio.csts & (NVME_CSTS_CFS | NVME_CSTS_SHST_MASK)) != 0;
}

/* Setup the controller guid and serial */
static void nvme_mdev_vctrl_init_id(struct nvme_mdev_vctrl *vctrl)
{
	// guid_t guid = mdev_uuid(vctrl->mdev);
	guid_t guid = vctrl->mdev->uuid;

	snprintf(vctrl->subnqn, sizeof(vctrl->subnqn),
		 "nqn.2014-08.org.nvmexpress:uuid:%pUl", guid.b);

	snprintf(vctrl->serial, sizeof(vctrl->serial), "%pUl", guid.b);
}

/* Change the IO thread CPU pinning */
void nvme_mdev_vctrl_bind_iothread(struct nvme_mdev_vctrl *vctrl,
				   unsigned int cpu)
{
	mutex_lock(&vctrl->lock);

	if (cpu == vctrl->iothread_cpu)
		goto out;

	nvme_mdev_io_free(vctrl);
	nvme_mdev_io_create(vctrl, cpu);
out:
	mutex_unlock(&vctrl->lock);
}

/* Change the status of support for shadow doorbell */
int nvme_mdev_vctrl_set_shadow_doorbell_supported(struct nvme_mdev_vctrl *vctrl,
						  bool enable)
{
	if (vctrl->inuse)
		return -EBUSY;
	vctrl->mmio.shadow_db_supported = enable;
	return 0;
}

/* Called when memory mapping are changed. Propagate this to all kmap users */
static void nvme_mdev_vctrl_viommu_update(struct nvme_mdev_vctrl *vctrl)
{
	u16 qid;

	lockdep_assert_held(&vctrl->lock);

	if (!(vctrl->mmio.csts & NVME_CSTS_RDY))
		return;

	/* update mappings for submission and completion queues */
	for_each_set_bit(qid, vctrl->vsq_en, MAX_VIRTUAL_QUEUES)
		nvme_mdev_vsq_viommu_update(&vctrl->viommu, &vctrl->vsqs[qid]);

	for_each_set_bit(qid, vctrl->vcq_en, MAX_VIRTUAL_QUEUES)
		nvme_mdev_vcq_viommu_update(&vctrl->viommu, &vctrl->vcqs[qid]);

	/* update mapping for the shadow doorbells */
	nvme_mdev_mmio_viommu_update(vctrl);
}

/* Create a new virtual controller */
struct nvme_mdev_vctrl *nvme_mdev_vctrl_create(struct mdev_device *mdev,
					       struct nvme_mdev_hctrl *hctrl,
					       unsigned int max_host_queues)
{
	int ret;
	struct nvme_mdev_vctrl *vctrl = kzalloc_node(sizeof(*vctrl),
						     GFP_KERNEL, hctrl->node);

	struct nvme_mdev_perf_data *perf_data = kzalloc_node(sizeof(struct nvme_mdev_perf_data), GFP_KERNEL, hctrl->node);

	if (!vctrl || !perf_data)
		return ERR_PTR(-ENOMEM);
	
	/* IO schd */
	vctrl->perf_data = perf_data;
	mutex_init(&(vctrl->perf_data->lock));
	
	/* Basic init */
	vctrl->hctrl = hctrl;
	vctrl->mdev = mdev;
	vctrl->max_host_hw_queues = max_host_queues;
	vctrl->viommu.vctrl = vctrl;

	kref_init(&vctrl->ref);
	mutex_init(&vctrl->lock);
	nvme_mdev_vctrl_init_id(vctrl);
	INIT_LIST_HEAD(&vctrl->host_hw_queues);
	mutex_init(&vctrl->host_hw_queues_lock);

	get_device(mdev_dev(mdev));
	mdev_set_drvdata(mdev, vctrl);

	/* reserve host IO queues */
	/* as we has bound queue for each vm, so this is not need now */
	// if (!nvme_mdev_hctrl_hqs_reserve(hctrl, max_host_queues)) {
	// 	ret = -ENOSPC;
	// 	goto error1;
	// }

	/* default feature values*/
	vctrl->arb_burst_shift = 3;
	vctrl->mmio.shadow_db_supported = use_shadow_doorbell;

	ret = nvme_mdev_pci_create(vctrl);
	if (ret)
		goto error2;

	ret = nvme_mdev_mmio_create(vctrl);
	if (ret)
		goto error3;

	nvme_mdev_irqs_setup(vctrl);

	/* Create the IO thread */
	/*TODOLATER: IO: smp_processor_id() is not an ideal pinning choice */
	ret = nvme_mdev_io_create(vctrl, smp_processor_id());
	if (ret)
		goto error4;

	_INFO(vctrl, "device created using %d host queues\n", max_host_queues);
	

	return vctrl;
error4:
	nvme_mdev_mmio_free(vctrl);
error3:
	nvme_mdev_pci_free(vctrl);
error2:
	nvme_mdev_hctrl_hqs_unreserve(hctrl, max_host_queues);
error1:
	put_device(mdev_dev(mdev));
	kfree(vctrl);
	return ERR_PTR(ret);
}

/*Try to destroy an vctrl */
int nvme_mdev_vctrl_destroy(struct nvme_mdev_vctrl *vctrl)
{
	mutex_lock(&vctrl->lock);

	if (vctrl->inuse) {
		/* vctrl has mdev users */
		mutex_unlock(&vctrl->lock);
		return -EBUSY;
	}

	_INFO(vctrl, "device is destroying\n");

	/* IO schd */
	nvme_mdev_vctrl_hq_unbind(vctrl);

	mdev_set_drvdata(vctrl->mdev, NULL);
	mutex_unlock(&vctrl->lock);

	mutex_lock(&nvme_mdev_vctrl_list_mutex);
	list_del_init(&vctrl->link);
	mutex_unlock(&nvme_mdev_vctrl_list_mutex);

	mutex_lock(&vctrl->lock); /*only for lockdep checks */
	nvme_mdev_io_free(vctrl);
	nvme_mdev_vns_destroy_all(vctrl);
	__nvme_mdev_vctrl_reset(vctrl, true);

	nvme_mdev_hctrl_hqs_unreserve(vctrl->hctrl, vctrl->max_host_hw_queues);

	nvme_mdev_pci_free(vctrl);
	nvme_mdev_mmio_free(vctrl);

	mutex_unlock(&vctrl->lock);

	put_device(mdev_dev(vctrl->mdev));
	_INFO(vctrl, "device is destroyed\n");
	kfree(vctrl);
	return 0;
}

/* Suspends a running virtual controller
 * Called when host needs to regain full control of the device
 */
void nvme_mdev_vctrl_pause(struct nvme_mdev_vctrl *vctrl)
{
	mutex_lock(&vctrl->lock);
	if (!vctrl->vctrl_paused) {
		_INFO(vctrl, "pausing the virtual controller\n");
		if (vctrl->mmio.csts & NVME_CSTS_RDY)
			nvme_mdev_io_pause(vctrl);
		vctrl->vctrl_paused = true;
	}
	mutex_unlock(&vctrl->lock);
}

/* Resumes a virtual controller
 * Called when host done with exclusive access and allows us
 * again to attach to the controller
 */
void nvme_mdev_vctrl_resume(struct nvme_mdev_vctrl *vctrl)
{
	mutex_lock(&vctrl->lock);
	nvme_mdev_assert_io_not_running(vctrl);

	if (vctrl->vctrl_paused) {
		_INFO(vctrl, "resuming the virtual controller\n");

		if (vctrl->mmio.csts & NVME_CSTS_RDY) {
			/* handle all pending admin commands*/
			nvme_mdev_adm_process_sq(vctrl);
			/* start the IO thread again if it was stopped or
			 * if we had doorbell writes during the pause
			 */
			nvme_mdev_io_resume(vctrl);
		}
		vctrl->vctrl_paused = false;
	}
	mutex_unlock(&vctrl->lock);
}

/* Called when emulator opens the virtual device */
int nvme_mdev_vctrl_open(struct nvme_mdev_vctrl *vctrl)
{
	struct device *dma_dev = NULL;
	int ret = 0;

	mutex_lock(&vctrl->lock);

	if (vctrl->hctrl->removing) {
		ret = -ENODEV;
		goto out;
	}

	if (vctrl->inuse) {
		ret = -EBUSY;
		goto out;
	}

	_INFO(vctrl, "device is opened\n");

	if (vctrl->hctrl->nvme_ctrl->ops->flags & NVME_F_MDEV_DMA_SUPPORTED)
		dma_dev = vctrl->hctrl->nvme_ctrl->dev;

	nvme_mdev_viommu_init(&vctrl->viommu, mdev_dev(vctrl->mdev), dma_dev);

	nvme_mdev_mmio_open(vctrl);
	vctrl->inuse = true;

	memset(&vctrl->perf, 0, sizeof(vctrl->perf));
	/* IO schd */
	vctrl->perf_data->phase = 0;
	vctrl->perf_data->rounds = 0;
out:
	mutex_unlock(&vctrl->lock);
	return ret;
}

/* Called when emulator closes the virtual device */
void nvme_mdev_vctrl_release(struct nvme_mdev_vctrl *vctrl)
{
	mutex_lock(&vctrl->lock);
	nvme_mdev_io_pause(vctrl);

	/* Remove the guest DMA mappings - new user that will open the
	 * device might be a different guest
	 */
	nvme_mdev_viommu_reset(&vctrl->viommu);

	/* Reset the controller to a clean state for a new user */
	__nvme_mdev_vctrl_reset(vctrl, false);

	nvme_mdev_irqs_reset(vctrl);
	vctrl->inuse = false;
	mutex_unlock(&vctrl->lock);

	WARN_ON(!list_empty(&vctrl->host_hw_queues));

	_INFO(vctrl, "device is released\n");

	/* If we are released after request to remove the host controller
	 * we are dead, won't be opened again ever, so remove ourselves
	 */
	if (vctrl->hctrl->removing)
		nvme_mdev_vctrl_destroy(vctrl);
}

/* Called each time the controller is reset (CC.EN <= 0 or VM level reset) */
void __nvme_mdev_vctrl_reset(struct nvme_mdev_vctrl *vctrl, bool pci_reset)
{
	lockdep_assert_held(&vctrl->lock);

	if ((vctrl->mmio.csts & NVME_CSTS_RDY) &&
	    !(vctrl->mmio.csts & NVME_CSTS_SHST_MASK)) {
		_DBG(vctrl, "unsafe reset (CSTS.RDY==1)\n");
		nvme_mdev_io_pause(vctrl);
		nvme_mdev_vctrl_disable(vctrl);
	}
	nvme_mdev_mmio_reset(vctrl, pci_reset);
}

/* setups initial admin queues and doorbells */
bool nvme_mdev_vctrl_enable(struct nvme_mdev_vctrl *vctrl,
			    dma_addr_t cqiova, dma_addr_t sqiova, u32 sizes)
{
	int ret;
	u16 cqentries, sqentries;

	nvme_mdev_assert_io_not_running(vctrl);

	lockdep_assert_held(&vctrl->lock);

	sqentries = (sizes & 0xFFFF) + 1;
	cqentries = (sizes >> 16) + 1;

	if (cqentries > 4096 || cqentries < 2)
		return false;
	if (sqentries > 4096 || sqentries < 2)
		return false;

	ret = nvme_mdev_mmio_enable_dbs(vctrl);
	if (ret)
		goto error0;

	ret = nvme_mdev_vcq_init(vctrl, 0, cqiova, true, cqentries, 0);
	if (ret)
		goto error1;

	ret = nvme_mdev_vsq_init(vctrl, 0, sqiova, true, sqentries, 0);
	if (ret)
		goto error2;

	nvme_mdev_events_init(vctrl);

	if (!vctrl->mmio.shadow_db_supported) {
		/* start polling right away to support admin queue */
		vctrl->io_idle = false;
		nvme_mdev_io_resume(vctrl);
	}

	return true;
error2:
	nvme_mdev_mmio_disable_dbs(vctrl);
error1:
	nvme_mdev_vcq_delete(vctrl, 0);
error0:
	return false;
}

/* destroy all io/admin queues on the controller  */
void nvme_mdev_vctrl_disable(struct nvme_mdev_vctrl *vctrl)
{
	u16 sqid, cqid;

	nvme_mdev_assert_io_not_running(vctrl);

	lockdep_assert_held(&vctrl->lock);

	nvme_mdev_events_reset(vctrl);
	nvme_mdev_vns_log_reset(vctrl);

	sqid = 1;
	for_each_set_bit_from(sqid, vctrl->vsq_en, MAX_VIRTUAL_QUEUES)
		nvme_mdev_vsq_delete(vctrl, sqid);

	cqid = 1;
	for_each_set_bit_from(cqid, vctrl->vcq_en, MAX_VIRTUAL_QUEUES)
		nvme_mdev_vcq_delete(vctrl, cqid);

	nvme_mdev_vsq_delete(vctrl, 0);
	nvme_mdev_vcq_delete(vctrl, 0);

	nvme_mdev_mmio_disable_dbs(vctrl);
	vctrl->io_idle = true;
}

/* External reset */
void nvme_mdev_vctrl_reset(struct nvme_mdev_vctrl *vctrl)
{
	mutex_lock(&vctrl->lock);
	_INFO(vctrl, "reset\n");
	__nvme_mdev_vctrl_reset(vctrl, true);
	mutex_unlock(&vctrl->lock);
}

/* Add IO region*/
void nvme_mdev_vctrl_add_region(struct nvme_mdev_vctrl *vctrl,
				unsigned int index, unsigned int size,
				region_access_fn access_fn)
{
	struct nvme_mdev_io_region *region = &vctrl->regions[index];

	region->size = size;
	region->rw = access_fn;
	region->mmap_ops = NULL;
}

/* Enable mmap window on an IO region */
void nvme_mdev_vctrl_region_set_mmap(struct nvme_mdev_vctrl *vctrl,
				     unsigned int index,
				     unsigned int offset,
				     unsigned int size,
				     const struct vm_operations_struct *ops)
{
	struct nvme_mdev_io_region *region = &vctrl->regions[index];

	region->mmap_area_start = offset;
	region->mmap_area_size = size;
	region->mmap_ops = ops;
}

/* Disable mmap window on an IO region */
void nvme_mdev_vctrl_region_disable_mmap(struct nvme_mdev_vctrl *vctrl,
					 unsigned int index)
{
	struct nvme_mdev_io_region *region = &vctrl->regions[index];

	region->mmap_area_start = 0;
	region->mmap_area_size = 0;
	region->mmap_ops = NULL;
}

void nvme_mdev_vctrl_hq_bind(struct nvme_mdev_vctrl *vctrl)
{
	struct nvme_mdev_hq *hq;
	mutex_lock(&vctrl->host_hw_queues_lock);
	hq = schd->host_hw_queues[vctrl->id];
	hq->vctrl_id = vctrl->id;
	hq->bound = true;
	pr_info("vctrl.c: bound hwq %d to vctrl %d.\n", hq->hqid, vctrl->id);
	if(list_empty(&vctrl->host_hw_queues))
		list_add_tail(&hq->link, &vctrl->host_hw_queues);
	mutex_unlock(&vctrl->host_hw_queues_lock);
}

void nvme_mdev_vctrl_hq_unbind(struct nvme_mdev_vctrl *vctrl)
{
	struct nvme_mdev_hq *hq;
	mutex_lock(&vctrl->host_hw_queues_lock);
	hq = schd->host_hw_queues[vctrl->id];
	hq->vctrl_id = 0;
	hq->bound = false;
	pr_info("vctrl.c: unbound hwq %d from vctrl %d.\n", hq->hqid, vctrl->id);
	if(!list_empty(&vctrl->host_hw_queues))
		list_del(&hq->link);
	mutex_unlock(&vctrl->host_hw_queues_lock);
}


/* Allocate a host IO queue */
int nvme_mdev_vctrl_hq_alloc(struct nvme_mdev_vctrl *vctrl)
{
	struct nvme_mdev_hq *hq = NULL;
	int i = 0, ret;

	lockdep_assert_held(&schd->lock);
	lockdep_assert_held(&vctrl->lock);

	nvme_mdev_assert_io_not_running(vctrl);

	nvme_mdev_vctrl_print_hwq(vctrl);
	/* IO schd */
	if (schd->nr_used_hwqs < schd->total_hwqs) {
		pr_info("vctrl.c: schd->nr_used_hwqs < schd->total_hwqs.\n");
		// for (i = 0; i < schd->total_hwqs; i++) {
		for (i = schd->mdev_device_num; i < schd->total_hwqs; i++) {
			printk("vctrl: schd device %d.\n", i);
			hq = schd->host_hw_queues[i];
			if (hq->usecount == 0)
				break;
		}

		if (!hq) {
			printk("vctrl: no available host queue, directly return and suspend virtual queue.\n");
			nvme_mdev_vctrl_print_hwq(vctrl);
			return 0;
		}

		hq->vctrl_id = vctrl->id;
		hq->usecount = 1;
		schd->nr_used_hwqs++;
		mutex_lock(&vctrl->host_hw_queues_lock);
		// list_del_init(&hq->link);
		list_add_tail(&hq->link, &vctrl->host_hw_queues);
		pr_info("vctrl.c: alloc: vctrl %d use bound hwq %d.\n", vctrl->id, hq->hqid);
		mutex_unlock(&vctrl->host_hw_queues_lock);
		nvme_mdev_vctrl_print_hwq(vctrl);
		
		return hq->hqid;
	} else {
		/* only the reserved hwq for each vm is overused now */
		/* and we only record the usecount of other host queues*/
		mutex_lock(&vctrl->host_hw_queues_lock);
		hq = schd->host_hw_queues[vctrl->id];
		pr_info("vctrl.c: alloc: vctrl %d use bound hwq %d.\n", vctrl->id, hq->hqid);
		mutex_unlock(&vctrl->host_hw_queues_lock);
		nvme_mdev_vctrl_print_hwq(vctrl);
		
		return hq->hqid;
	}
}

/* Free a host IO queue */
void nvme_mdev_vctrl_hq_free(struct nvme_mdev_vctrl *vctrl, u16 hqid)
{
	struct nvme_mdev_hq *hq;
	int i;

	lockdep_assert_held(&schd->lock);
	lockdep_assert_held(&vctrl->lock);
	
	nvme_mdev_assert_io_not_running(vctrl);

	nvme_mdev_vctrl_print_hwq(vctrl);

	mutex_lock(&vctrl->host_hw_queues_lock);
	list_for_each_entry(hq, &vctrl->host_hw_queues, link) {
		if (hq->hqid == hqid && !hq->bound) {
			pr_info("vctrl.c: free hq !hq->bound %d.\n");
			hq->usecount = 0;
			schd->nr_used_hwqs--;
			list_del_init(&hq->link);
			mutex_unlock(&vctrl->host_hw_queues_lock);
			nvme_mdev_vctrl_print_hwq(vctrl);
			return;
		}
		if (hq->hqid == hqid && hq->bound) {
			pr_info("vctrl.c: free hq hq->bound %d.\n");
			mutex_unlock(&vctrl->host_hw_queues_lock);
			nvme_mdev_vctrl_print_hwq(vctrl);
			return;
		}
	}
	mutex_unlock(&vctrl->host_hw_queues_lock);
	WARN_ON(1);
}

/* get current list of host queues */
unsigned int nvme_mdev_vctrl_hqs_list(struct nvme_mdev_vctrl *vctrl, u16 *out)
{
	struct nvme_mdev_hq *q;
	unsigned int i = 0;

	mutex_lock(&vctrl->host_hw_queues_lock);

	list_for_each_entry(q, &vctrl->host_hw_queues, link) {
		out[i++] = q->hqid;
		if (WARN_ON(i > MAX_HOST_QUEUES)) {
			// i = 0;
			break;
		}
	}

	mutex_unlock(&vctrl->host_hw_queues_lock);
	return i;
}

/* add a user memory mapping */
int nvme_mdev_vctrl_viommu_map(struct nvme_mdev_vctrl *vctrl, u32 flags,
			       dma_addr_t iova, u64 size)
{
	int ret;

	mutex_lock(&vctrl->lock);

	nvme_mdev_io_pause(vctrl);
	ret = nvme_mdev_viommu_add(&vctrl->viommu, flags, iova, size);
	nvme_mdev_vctrl_viommu_update(vctrl);
	nvme_mdev_io_resume(vctrl);

	mutex_unlock(&vctrl->lock);
	return ret;
}

/* remove a user memory mapping */
int nvme_mdev_vctrl_viommu_unmap(struct nvme_mdev_vctrl *vctrl,
				 dma_addr_t iova, u64 size)
{
	int ret;

	mutex_lock(&vctrl->lock);

	nvme_mdev_io_pause(vctrl);
	ret = nvme_mdev_viommu_remove(&vctrl->viommu, iova, size);
	nvme_mdev_vctrl_viommu_update(vctrl);
	nvme_mdev_io_resume(vctrl);

	mutex_unlock(&vctrl->lock);
	return ret;
}

void nvme_mdev_vctrl_print_hwq(struct nvme_mdev_vctrl *vctrl)
{
	u16 hsqcnt;
	u16 hsqs[MAX_HOST_QUEUES];
	char buf[100] = {'0'};
	int i = 0, j = 0;

	hsqcnt = nvme_mdev_vctrl_hqs_list(vctrl, hsqs);
	for (i = 0; i < hsqcnt; i++) {
		j = sprintf(buf + j, "%d, ", hsqs[i]);
	}
	pr_info("vctrl %d has hwq %s.\n", vctrl->id, buf);
}

