// SPDX-License-Identifier: GPL-2.0+
/*
 * Mediated NVMe instance VFIO code
 * Copyright (c) 2019 - Maxim Levitsky
 */

#include <linux/init.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/vfio.h>
#include <linux/sysfs.h>
#include <linux/mdev.h>
#include <linux/kthread.h>
#include "priv.h"

#define DEBUG

#define OFFSET_TO_REGION(offset) ((offset) >> 20)
#define REGION_TO_OFFSET(nr) (((u64)nr) << 20)

LIST_HEAD(nvme_mdev_vctrl_list);
/*protects the list */
DEFINE_MUTEX(nvme_mdev_vctrl_list_mutex);

struct mdev_nvme_vfio_region_info {
	struct vfio_region_info base;
	struct vfio_region_info_cap_sparse_mmap mmap_cap;
};

/* User memory added*/
static int nvme_mdev_map_notifier(struct notifier_block *nb,
				  unsigned long action, void *data)
{
	struct vfio_iommu_type1_dma_map *map = data;
	struct nvme_mdev_vctrl *vctrl =
		container_of(nb, struct nvme_mdev_vctrl, vfio_map_notifier);

	int ret = nvme_mdev_vctrl_viommu_map(vctrl, map->flags,
			map->iova, map->size);
	return ret ? NOTIFY_OK : notifier_from_errno(ret);
}

/* User memory removed*/
static int nvme_mdev_unmap_notifier(struct notifier_block *nb,
				    unsigned long action, void *data)
{
	struct nvme_mdev_vctrl *vctrl =
		container_of(nb, struct nvme_mdev_vctrl, vfio_unmap_notifier);
	struct vfio_iommu_type1_dma_unmap *unmap = data;

	int ret = nvme_mdev_vctrl_viommu_unmap(vctrl, unmap->iova, unmap->size);

	WARN_ON(ret <= 0);
	return NOTIFY_OK;
}




/* Called when new mediated device is created */
static int nvme_mdev_ops_create(struct mdev_device *mdev)
{
	struct mdev_type *mtype = mdev->type;
	struct kobject   *kobj  = &mtype->kobj;
	
	int ret = 0;
	const struct nvme_mdev_inst_type *type = NULL;
	struct nvme_mdev_vctrl *vctrl;
	struct nvme_mdev_hctrl *hctrl = NULL;

	hctrl = nvme_mdev_hctrl_lookup_get(mdev_parent_dev(mdev));
	if (!hctrl) {
		return -ENODEV; 
	}

	type = nvme_mdev_inst_type_get(kobj->name);
	pr_info("instance.c: create mdev device with %d max hw queues.\n", type->max_hw_queues);
	vctrl = nvme_mdev_vctrl_create(mdev, hctrl, type->max_hw_queues);

	if (IS_ERR(vctrl)) {
		ret = PTR_ERR(vctrl);
		goto out;
	}

	mutex_lock(&nvme_mdev_vctrl_list_mutex);
	list_add_tail(&vctrl->link, &nvme_mdev_vctrl_list);
	mutex_unlock(&nvme_mdev_vctrl_list_mutex);
out:
	nvme_mdev_hctrl_put(hctrl);
	return ret;
}

/* Called when a mediated device is removed */
static int nvme_mdev_ops_remove(struct mdev_device *mdev)
{
	int ret = -1;
	struct nvme_mdev_vctrl *vctrl = mdev_to_vctrl(mdev);

	if (!vctrl)
		return -ENODEV;
	return nvme_mdev_vctrl_destroy(vctrl);
}

/* Called when new mediated device is opened by a user */
static int nvme_mdev_ops_open(struct mdev_device *mdev)
{
	int ret;
	unsigned long events;
	struct nvme_mdev_vctrl *vctrl = mdev_to_vctrl(mdev);
	struct nvme_mdev_hq *hq;

	if (!vctrl)
		return -ENODEV;

	schd_add_vctrl(vctrl);
	pr_info("IO schd: add vclient %d schd current client %d.\n", vctrl->id, schd->curr_client);
	/* IO schd */
	nvme_mdev_vctrl_hq_bind(vctrl);

	ret =  nvme_mdev_vctrl_open(vctrl);
	if (ret)
		return ret;

	/* register unmap IOMMU notifier*/
	vctrl->vfio_unmap_notifier.notifier_call = nvme_mdev_unmap_notifier;
	events = VFIO_IOMMU_NOTIFY_DMA_UNMAP;

	ret = vfio_register_notifier(mdev_dev(vctrl->mdev),
				     VFIO_IOMMU_NOTIFY, &events,
				     &vctrl->vfio_unmap_notifier);

	if (ret != 0) {
		nvme_mdev_vctrl_release(vctrl);
		return ret;
	}

	/* register map IOMMU notifier*/
	vctrl->vfio_map_notifier.notifier_call = nvme_mdev_map_notifier;
	events = VFIO_IOMMU_NOTIFY_DMA_MAP;

	ret = vfio_register_notifier(mdev_dev(vctrl->mdev),
				     VFIO_IOMMU_NOTIFY, &events,
				     &vctrl->vfio_map_notifier);

	if (ret != 0) {
		vfio_unregister_notifier(mdev_dev(vctrl->mdev),
					 VFIO_IOMMU_NOTIFY,
					 &vctrl->vfio_unmap_notifier);
		nvme_mdev_vctrl_release(vctrl);
		return ret;
	}

	return ret;
}

/* Called when new mediated device is closed (last close of the user) */
static void nvme_mdev_ops_release(struct mdev_device *mdev)
{
	struct nvme_mdev_vctrl *vctrl = mdev_to_vctrl(mdev);
	int ret;

	mutex_lock(&schd->lock);
	if (!schd->thread_parked) {
		schd->thread_parked = true;
		kthread_park(tsk);
	}
	mutex_unlock(&schd->lock);

	

	ret = vfio_unregister_notifier(mdev_dev(vctrl->mdev),
				       VFIO_IOMMU_NOTIFY,
				       &vctrl->vfio_unmap_notifier);
	WARN_ON(ret);

	ret = vfio_unregister_notifier(mdev_dev(vctrl->mdev),
				       VFIO_IOMMU_NOTIFY,
				       &vctrl->vfio_map_notifier);
	WARN_ON(ret);

	/* IO schd */
	ret = schd_remove_vctrl(vctrl); 
	pr_info("IO schd: %d vctrl left\n", ret);

	nvme_mdev_vctrl_release(vctrl);

	mutex_lock(&schd->lock);
	if (schd->thread_parked) {
		schd->thread_parked = false;
		kthread_unpark(tsk);
	}
	mutex_unlock(&schd->lock);
}

/* Helper function for bar/pci config read/write access */
static ssize_t nvme_mdev_access(struct nvme_mdev_vctrl *vctrl,
				char *buf, size_t count,
				loff_t pos, bool is_write)
{
	int index = OFFSET_TO_REGION(pos);
	int ret = -EINVAL;
	unsigned int offset;

	if (index >= VFIO_PCI_NUM_REGIONS || !vctrl->regions[index].rw)
		goto out;

	offset = pos - REGION_TO_OFFSET(index);
	if (offset + count > vctrl->regions[index].size)
		goto out;

	ret = vctrl->regions[index].rw(vctrl, offset, buf, count, is_write);
out:
	return ret;
}

/* Called when read() is done on the device */
static ssize_t nvme_mdev_ops_read(struct mdev_device *mdev, char __user *buf,
				  size_t count, loff_t *ppos)
{
	unsigned int done = 0;
	int ret;
	struct nvme_mdev_vctrl *vctrl = mdev_to_vctrl(mdev);

	if (!vctrl)
		return -ENODEV;

	while (count) {
		size_t filled;

		if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			ret = nvme_mdev_access(vctrl, (char *)&val,
					       sizeof(val), *ppos, false);
			if (ret <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;
			filled = sizeof(val);
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			ret = nvme_mdev_access(vctrl, (char *)&val,
					       sizeof(val), *ppos, false);
			if (ret <= 0)
				goto read_err;
			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;
			filled = sizeof(val);
		} else {
			u8 val;

			ret = nvme_mdev_access(vctrl, (char *)&val,
					       sizeof(val), *ppos, false);
			if (ret <= 0)
				goto read_err;
			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;
			filled = sizeof(val);
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}
	return done;
read_err:
	return -EFAULT;
}

/* Called when write() is done on the device */
static ssize_t nvme_mdev_ops_write(struct mdev_device *mdev,
				   const char __user *buf,
				   size_t count, loff_t *ppos)
{
	unsigned int done = 0;
	int ret;
	struct nvme_mdev_vctrl *vctrl = mdev_to_vctrl(mdev);

	if (!vctrl)
		return -ENODEV;

	while (count) {
		size_t filled;

		if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;
			ret = nvme_mdev_access(vctrl, (char *)&val,
					       sizeof(val), *ppos, true);
			if (ret <= 0)
				goto write_err;
			filled = sizeof(val);
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			ret = nvme_mdev_access(vctrl, (char *)&val,
					       sizeof(val), *ppos, true);
			if (ret <= 0)
				goto write_err;
			filled = sizeof(val);
		} else {
			u8 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;
			ret = nvme_mdev_access(vctrl, (char *)&val,
					       sizeof(val), *ppos, true);
			if (ret <= 0)
				goto write_err;
			filled = sizeof(val);
		}
		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}
	return done;
write_err:
	return -EFAULT;
}

/*Helper for IRQ number VFIO query */
static int nvme_mdev_irq_counts(struct nvme_mdev_vctrl *vctrl,
				unsigned int irq_type)
{
	switch (irq_type) {
	case VFIO_PCI_INTX_IRQ_INDEX:
		return 1;
	case VFIO_PCI_MSIX_IRQ_INDEX:
		return MAX_VIRTUAL_IRQS;
	case VFIO_PCI_REQ_IRQ_INDEX:
		return 1;
	default:
		return 0;
	}
}

/* VFIO VFIO_IRQ_SET_ACTION_TRIGGER implementation */
static int nvme_mdev_ioctl_set_irqs_trigger(struct nvme_mdev_vctrl *vctrl,
					    u32 flags,
					    unsigned int irq_type,
					    unsigned int start,
					    unsigned int count,
					    void *data)
{
	u32 data_type = flags & VFIO_IRQ_SET_DATA_TYPE_MASK;
	u8 *bools = NULL;
	unsigned int i;
	int ret = -EINVAL;

	/* Asked to disable the current interrupt mode*/
	if (data_type == VFIO_IRQ_SET_DATA_NONE && count == 0) {
		switch (irq_type) {
		case VFIO_PCI_REQ_IRQ_INDEX:
			nvme_mdev_irqs_set_unplug_trigger(vctrl, -1);
			return 0;
		case VFIO_PCI_INTX_IRQ_INDEX:
			nvme_mdev_irqs_disable(vctrl, NVME_MDEV_IMODE_INTX);
			return 0;
		case VFIO_PCI_MSIX_IRQ_INDEX:
			nvme_mdev_irqs_disable(vctrl, NVME_MDEV_IMODE_MSIX);
			return 0;
		default:
			return -EINVAL;
		}
	}

	if (start + count > nvme_mdev_irq_counts(vctrl, irq_type))
		return -EINVAL;

	switch (data_type) {
	case VFIO_IRQ_SET_DATA_BOOL:
		bools = (u8 *)data;
		/*fallthrough*/
	case VFIO_IRQ_SET_DATA_NONE:
		if (irq_type == VFIO_PCI_REQ_IRQ_INDEX)
			return -EINVAL;

		for (i = 0 ; i < count ; i++) {
			int index = start + i;

			if (!bools || bools[i])
				nvme_mdev_irq_trigger(vctrl, index);
		}
		return 0;

	case VFIO_IRQ_SET_DATA_EVENTFD:
		switch (irq_type) {
		case VFIO_PCI_REQ_IRQ_INDEX:
			return nvme_mdev_irqs_set_unplug_trigger(vctrl,
							*(int32_t *)data);
		case VFIO_PCI_INTX_IRQ_INDEX:
			ret = nvme_mdev_irqs_enable(vctrl,
						    NVME_MDEV_IMODE_INTX);
			break;
		case VFIO_PCI_MSIX_IRQ_INDEX:
			ret = nvme_mdev_irqs_enable(vctrl,
						    NVME_MDEV_IMODE_MSIX);
			break;
		default:
			return -EINVAL;
		}
		if (ret)
			return ret;

		return nvme_mdev_irqs_set_triggers(vctrl, start,
						   count, (int32_t *)data);
	default:
		return -EINVAL;
	}
}

/* VFIO_DEVICE_GET_INFO ioctl implementation */
static int nvme_mdev_ioctl_get_info(struct nvme_mdev_vctrl *vctrl,
				    void __user *arg)
{
	struct vfio_device_info info;
	unsigned int minsz = offsetofend(struct vfio_device_info, num_irqs);

	if (copy_from_user(&info, (void __user *)arg, minsz))
		return -EFAULT;
	if (info.argsz < minsz)
		return -EINVAL;

	info.flags = VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET;
	info.num_regions = VFIO_PCI_NUM_REGIONS;
	info.num_irqs = VFIO_PCI_NUM_IRQS;

	if (copy_to_user(arg, &info, minsz))
		return -EFAULT;
	return 0;
}

/* VFIO_DEVICE_GET_REGION_INFO ioctl implementation*/
static int nvme_mdev_ioctl_get_reg_info(struct nvme_mdev_vctrl *vctrl,
					void __user *arg)
{
	struct nvme_mdev_io_region *region;
	struct mdev_nvme_vfio_region_info *info;
	unsigned long minsz, outsz, maxsz;
	int ret = 0;

	minsz = offsetofend(struct vfio_region_info, offset);
	maxsz = sizeof(struct mdev_nvme_vfio_region_info) +
				sizeof(struct vfio_region_sparse_mmap_area);

	info = kzalloc(maxsz, GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	if (copy_from_user(info, arg, minsz)) {
		ret = -EFAULT;
		goto out;
	}

	outsz = info->base.argsz;
	if (outsz < minsz || outsz > maxsz) {
		ret = -EINVAL;
		goto out;
	}

	if (info->base.index >= VFIO_PCI_NUM_REGIONS) {
		ret = -EINVAL;
		goto out;
	}

	region = &vctrl->regions[info->base.index];
	info->base.offset = REGION_TO_OFFSET(info->base.index);
	info->base.argsz = maxsz;
	info->base.size = region->size;

	info->base.flags = VFIO_REGION_INFO_FLAG_READ |
				VFIO_REGION_INFO_FLAG_WRITE;

	if (region->mmap_ops) {
		info->base.flags |= (VFIO_REGION_INFO_FLAG_MMAP |
						VFIO_REGION_INFO_FLAG_CAPS);

		info->base.cap_offset =
			offsetof(struct mdev_nvme_vfio_region_info, mmap_cap);

		info->mmap_cap.header.id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;
		info->mmap_cap.header.version = 1;
		info->mmap_cap.header.next = 0;
		info->mmap_cap.nr_areas = 1;
		info->mmap_cap.areas[0].offset = region->mmap_area_start;
		info->mmap_cap.areas[0].size = region->mmap_area_size;
	}

	if (copy_to_user(arg, info, outsz))
		ret = -EFAULT;
out:
	kfree(info);
	return ret;
}

/* VFIO_DEVICE_GET_IRQ_INFO ioctl implementation */
static int nvme_mdev_ioctl_get_irq_info(struct nvme_mdev_vctrl *vctrl,
					void __user *arg)
{
	struct vfio_irq_info info;
	unsigned int minsz = offsetofend(struct vfio_irq_info, count);

	if (copy_from_user(&info, arg, minsz))
		return -EFAULT;
	if (info.argsz < minsz)
		return -EINVAL;

	info.count = nvme_mdev_irq_counts(vctrl, info.index);
	info.flags = VFIO_IRQ_INFO_EVENTFD;

	if (info.index == VFIO_PCI_INTX_IRQ_INDEX)
		info.flags |= VFIO_IRQ_INFO_MASKABLE | VFIO_IRQ_INFO_AUTOMASKED;

	if (copy_to_user(arg, &info, minsz))
		return -EFAULT;
	return 0;
}

/* VFIO VFIO_DEVICE_SET_IRQS ioctl implementation */
static int nvme_mdev_ioctl_set_irqs(struct nvme_mdev_vctrl *vctrl,
				    void __user *arg)
{
	int ret, irqcount;
	struct vfio_irq_set hdr;
	u8 *data = NULL;
	size_t data_size = 0;
	unsigned long minsz = offsetofend(struct vfio_irq_set, count);

	if (copy_from_user(&hdr, arg, minsz))
		return -EFAULT;

	irqcount = nvme_mdev_irq_counts(vctrl, hdr.index);
	ret = vfio_set_irqs_validate_and_prepare(&hdr,
						 irqcount,
						 VFIO_PCI_NUM_IRQS,
						 &data_size);
	if (ret)
		return ret;

	if (data_size) {
		data = memdup_user((arg + minsz), data_size);
		if (IS_ERR(data))
			return PTR_ERR(data);
	}

	ret = -ENOTTY;
	switch (hdr.index) {
	case VFIO_PCI_INTX_IRQ_INDEX:
	case VFIO_PCI_MSIX_IRQ_INDEX:
	case VFIO_PCI_REQ_IRQ_INDEX:
		switch (hdr.flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
		case VFIO_IRQ_SET_ACTION_UNMASK:
			// pretend to support this (even with eventfd)
			ret = hdr.index == VFIO_PCI_INTX_IRQ_INDEX ?
					0 : -EINVAL;
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
			ret = nvme_mdev_ioctl_set_irqs_trigger(vctrl, hdr.flags,
							       hdr.index,
							       hdr.start,
							       hdr.count,
							       data);
			break;
		}
		break;
	}

	kfree(data);
	return ret;
}

/* ioctl() implementation */
static long nvme_mdev_ops_ioctl(struct mdev_device *mdev, unsigned int cmd,
				unsigned long arg)
{
	struct nvme_mdev_vctrl *vctrl = mdev_get_drvdata(mdev);

	if (!vctrl)
		return -ENODEV;

	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
		return nvme_mdev_ioctl_get_info(vctrl, (void __user *)arg);
	case VFIO_DEVICE_GET_REGION_INFO:
		return nvme_mdev_ioctl_get_reg_info(vctrl, (void __user *)arg);
	case VFIO_DEVICE_GET_IRQ_INFO:
		return nvme_mdev_ioctl_get_irq_info(vctrl, (void __user *)arg);
	case VFIO_DEVICE_SET_IRQS:
		return nvme_mdev_ioctl_set_irqs(vctrl, (void __user *)arg);
	case VFIO_DEVICE_RESET:
		nvme_mdev_vctrl_reset(vctrl);
		return 0;
	default:
		return -ENOTTY;
	}
}

/* mmap() implementation (doorbell area) */
static int nvme_mdev_ops_mmap(struct mdev_device *mdev,
			      struct vm_area_struct *vma)
{
	struct nvme_mdev_vctrl *vctrl = mdev_get_drvdata(mdev);
	int index = OFFSET_TO_REGION((u64)vma->vm_pgoff << PAGE_SHIFT);
	unsigned long size, start;

	if (!vctrl)
		return -EFAULT;

	if (index >= VFIO_PCI_NUM_REGIONS || !vctrl->regions[index].mmap_ops)
		return -EINVAL;

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;

	size = vma->vm_end - vma->vm_start;
	start = vma->vm_pgoff << PAGE_SHIFT;

	if (start < vctrl->regions[index].mmap_area_start)
		return -EINVAL;
	if (size > vctrl->regions[index].mmap_area_size)
		return -EINVAL;

	if ((vma->vm_flags & VM_SHARED) == 0)
		return -EINVAL;

	vma->vm_ops = vctrl->regions[index].mmap_ops;
	vma->vm_private_data = vctrl;
	return 0;
}

/* Request removal of the device*/
static void nvme_mdev_ops_request(struct mdev_device *mdev, unsigned int count)
{
	struct nvme_mdev_vctrl *vctrl = mdev_get_drvdata(mdev);

	if (vctrl)
		nvme_mdev_irq_raise_unplug_event(vctrl, count);
}

/* Adding a new namespace given host NS id and partition ID (e/g. n1p2 or n1) */
static ssize_t add_namespace_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct nvme_mdev_vctrl *vctrl = dev_to_vctrl(dev);
	int ret;
	unsigned long partno = 0, nsid;
	char *buf_copy, *token, *tmp;

	if (!vctrl)
		return -ENODEV;

	buf_copy = kstrdup(buf, GFP_KERNEL);
	if (!buf_copy)
		return -ENOMEM;

	tmp = buf_copy;
	if (tmp[0] != 'n') {
		ret = -EINVAL;
		goto out;
	}
	tmp++;

	// read namespace ID (mandatory)
	token = strsep(&tmp, "p");
	if (!token) {
		ret = -EINVAL;
		goto out;
	}
	ret = kstrtoul(token, 10, &nsid);
	if (ret)
		goto out;

	// read partition ID (optional)
	if (tmp) {
		ret = kstrtoul(tmp, 10, &partno);
		if (ret)
			goto out;
	}

	// create the user namespace
	ret = nvme_mdev_vns_open(vctrl, nsid, partno);
	if (ret)
		goto out;
	ret = count;
out:
	kfree(buf_copy);
	return ret;
}
static DEVICE_ATTR_WO(add_namespace);

/* Remove a user namespace */
static ssize_t remove_namespace_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	unsigned long user_nsid;
	int ret;
	struct nvme_mdev_vctrl *vctrl = dev_to_vctrl(dev);

	if (!vctrl)
		return -ENODEV;

	ret = kstrtoul(buf, 10, &user_nsid);
	if (ret)
		return ret;

	ret =  nvme_mdev_vns_destroy(vctrl, user_nsid);
	if (ret)
		return ret;
	return count;
}
static DEVICE_ATTR_WO(remove_namespace);

/* Show list of user namespaces */
static ssize_t namespaces_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct nvme_mdev_vctrl *vctrl = dev_to_vctrl(dev);

	if (!vctrl)
		return -ENODEV;
	return nvme_mdev_vns_print_description(vctrl, buf, PAGE_SIZE - 1);
}
static DEVICE_ATTR_RO(namespaces);

/* change the cpu binding of the IO threads*/
static ssize_t iothread_cpu_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	unsigned long val;
	int ret;
	struct nvme_mdev_vctrl *vctrl = dev_to_vctrl(dev);

	if (!vctrl)
		return -ENODEV;
	ret = kstrtoul(buf, 10, &val);
	if (ret)
		return ret;
	nvme_mdev_vctrl_bind_iothread(vctrl, val);
	return count;
}

/* change the cpu binding of the IO threads*/
static ssize_t
iothread_cpu_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct nvme_mdev_vctrl *vctrl = dev_to_vctrl(dev);

	if (!vctrl)
		return -ENODEV;
	return sprintf(buf, "%d\n", vctrl->iothread_cpu);
}
static DEVICE_ATTR_RW(iothread_cpu);

/* change the cpu binding of the IO threads*/
static ssize_t shadow_doorbell_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	bool val;
	int ret;
	struct nvme_mdev_vctrl *vctrl = dev_to_vctrl(dev);

	if (!vctrl)
		return -ENODEV;
	ret = kstrtobool(buf, &val);
	if (ret)
		return ret;
	ret = nvme_mdev_vctrl_set_shadow_doorbell_supported(vctrl, val);
	if (ret)
		return ret;
	return count;
}

/* change the cpu binding of the IO threads*/
static ssize_t shadow_doorbell_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct nvme_mdev_vctrl *vctrl = dev_to_vctrl(dev);

	if (!vctrl)
		return -ENODEV;

	return sprintf(buf, "%d\n", vctrl->mmio.shadow_db_supported ? 1 : 0);
}
static DEVICE_ATTR_RW(shadow_doorbell);

static ssize_t qos_show(struct device *dev,
                        struct device_attribute *attr,
                        char *buf)
{
    struct nvme_mdev_vctrl *vctrl = dev_to_vctrl(dev);
    unsigned long type;

    if (!vctrl)
        return -ENODEV;

    type = (unsigned long)vctrl->type;

    return sprintf(buf, "%lu\n", type);
}

static ssize_t qos_store(struct device *dev,
                         struct device_attribute *attr,
                         const char *buf, size_t count)
{
    unsigned long type;
    int ret;
    struct nvme_mdev_vctrl *vctrl = dev_to_vctrl(dev);

    pr_info("qos store %s\n", buf); 
    if (!vctrl)
        return -ENODEV;
    ret = kstrtoul(buf, 10, &type);
    if (ret)
        return ret;

    if (!type)
        return -EINVAL;

    vctrl->type = (unsigned int)type;
    return type;
}

static DEVICE_ATTR_RW(qos);

static ssize_t qos_val_show(struct device *dev,
			   struct device_attribute *attr,
			   char *buf)
{
    struct nvme_mdev_vctrl *vctrl = dev_to_vctrl(dev);
    unsigned long qos_val;


    if (!vctrl)
        return -ENODEV;

    qos_val = (unsigned long)vctrl->qos_val;

    return sprintf(buf, "%lu\n", qos_val);
}

static ssize_t qos_val_store(struct device *dev,
                            struct device_attribute *attr,
                            const char *buf, size_t count)
{
    unsigned long qos_val;
    int ret;
    struct nvme_mdev_vctrl *vctrl = dev_to_vctrl(dev);

    pr_info("qos val store %s\n", buf); 
    if (!vctrl)
        return -ENODEV;
    ret = kstrtoul(buf, 10, &qos_val);
    if (ret)
        return ret;

    vctrl->qos_val = (unsigned int)qos_val;
    return qos_val;
}

static DEVICE_ATTR_RW(qos_val);

static struct attribute *nvme_mdev_dev_ns_atttributes[] = {
	&dev_attr_add_namespace.attr,
	&dev_attr_remove_namespace.attr,
	&dev_attr_namespaces.attr,
	NULL
};

static struct attribute *nvme_mdev_dev_settings_atttributes[] = {
	&dev_attr_iothread_cpu.attr,
	&dev_attr_shadow_doorbell.attr,
	&dev_attr_qos.attr,
	&dev_attr_qos_val.attr,
	NULL
};


/* show perf stats */
static ssize_t stats_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct nvme_mdev_vctrl *vctrl = dev_to_vctrl(dev);
	struct nvme_mdev_perf *perf;

	if (!vctrl)
		return -ENODEV;

	perf = &vctrl->perf;

	return sprintf(buf,
		"%u %llu %llu %llu %llu %llu %llu\n",

		tsc_khz,

		perf->cmds_started,
		perf->cycles_send_to_hw,

		perf->cmds_complete,
		perf->cycles_receive_from_hw,

		perf->interrupts_sent,
		perf->cycles_irq_delivery);
}

/* clear the perf stats */
static ssize_t stats_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	bool val;
	int ret;
	struct nvme_mdev_vctrl *vctrl = dev_to_vctrl(dev);

	if (!vctrl)
		return -ENODEV;
	ret = kstrtobool(buf, &val);
	if (ret)
		return ret;

	if (!val)
		return -EINVAL;

	memset(&vctrl->perf, 0, sizeof(vctrl->perf));
	return count;
}

static DEVICE_ATTR_RW(stats);


static struct attribute *nvme_mdev_dev_debug_attributes[] = {
	&dev_attr_stats.attr,
	NULL
};

static const struct attribute_group nvme_mdev_ns_attr_group = {
	.name = "namespaces",
	.attrs = nvme_mdev_dev_ns_atttributes,
};

static const struct attribute_group nvme_mdev_setting_attr_group = {
	.name = "settings",
	.attrs = nvme_mdev_dev_settings_atttributes,
};


static const struct attribute_group nvme_mdev_debug_attr_group = {
	.name = "debug",
	.attrs = nvme_mdev_dev_debug_attributes,
};

static const struct attribute_group *nvme_mdev_dev_attributte_groups[] = {
	&nvme_mdev_ns_attr_group,
	&nvme_mdev_setting_attr_group,
	&nvme_mdev_debug_attr_group,
	NULL,
};

struct mdev_parent_ops mdev_fops = {
	.owner			= THIS_MODULE,
	.create			= nvme_mdev_ops_create,
	.remove			= nvme_mdev_ops_remove,
	.open_device	= nvme_mdev_ops_open,
	.close_device	= nvme_mdev_ops_release,
	.read			= nvme_mdev_ops_read,
	.write			= nvme_mdev_ops_write,
	.mmap			= nvme_mdev_ops_mmap,
	.ioctl			= nvme_mdev_ops_ioctl,
	.request		= nvme_mdev_ops_request,
	.mdev_attr_groups	= nvme_mdev_dev_attributte_groups,
	.dev_attr_groups	= NULL,
};

