// SPDX-License-Identifier: GPL-2.0+
/*
 * Virtual NVMe namespace implementation
 * Copyright (c) 2019 - Maxim Levitsky
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/nvme.h>
#include "priv.h"

/* Reset the changed namespace log */
void nvme_mdev_vns_log_reset(struct nvme_mdev_vctrl *vctrl)
{
	vctrl->ns_log_size = 0;
}

/* This adds entry to NS changed log and sends to the user a notification */
static void nvme_mdev_vns_send_event(struct nvme_mdev_vctrl *vctrl, u32 ns)
{
	unsigned int i;
	unsigned int log_size = vctrl->ns_log_size;

	lockdep_assert_held(&vctrl->lock);

	_INFO(vctrl, "host namespace list rescanned\n");

	if (WARN_ON(ns == 0 || ns > MAX_VIRTUAL_NAMESPACES))
		return;

	// check if the namespace ID is alredy in the log
	if (log_size == MAX_VIRTUAL_NAMESPACES)
		return;

	for (i = 0; i < log_size; i++)
		if (vctrl->ns_log[i] == cpu_to_le32(ns))
			return;

	vctrl->ns_log[log_size++] = cpu_to_le32(ns);
	vctrl->ns_log_size++;
	nvme_mdev_event_send(vctrl, NVME_AER_TYPE_NOTICE,
			     NVME_AER_NOTICE_NS_CHANGED);
}

/* Read host NS/partition parameters to update our virtual NS */
static void nvme_mdev_vns_read_host_properties(struct nvme_mdev_vctrl *vctrl,
					       struct nvme_mdev_vns *vns,
					       struct nvme_ns *host_ns)
{
	unsigned int sector_to_lba_shift;
	u64 host_ns_size, start, nr, align_mask;

	lockdep_assert_held(&vctrl->lock);

	/* read the namespace block size */
	vns->blksize_shift = host_ns->lba_shift;

	if (WARN_ON(vns->blksize_shift < 9)) {
		_WARN(vctrl, "NS/create: device block size is bad\n");
		goto error;
	}

	sector_to_lba_shift = vns->blksize_shift - 9;
	align_mask = (1ULL << sector_to_lba_shift) - 1;

	/* read the partition start and size*/
	start = get_start_sect(vns->host_part);
	// nr = part_nr_sects_read(vns->host_part->bd_part);
	nr = bdev_nr_sectors(vns->host_part);

	/* check that partition is aligned on LBA size*/
	if (sector_to_lba_shift != 0) {
		if ((start & align_mask) || (nr & align_mask)) {
			_WARN(vctrl, "NS/create: partition not aligned\n");
			goto error;
		}
	}

	vns->host_lba_offset = start >> sector_to_lba_shift;
	vns->ns_size = nr >> sector_to_lba_shift;
	host_ns_size = get_capacity(host_ns->disk) >> sector_to_lba_shift;

	/*TODOLATER: NS: support metadata on host namespace */
	if (host_ns->ms) {
		_WARN(vctrl, "NS/create: no support for namespace metadata\n");
		goto error;
	}

	if (vns->ns_size == 0) {
		_WARN(vctrl, "NS/create: host namespace has size 0\n");
		goto error;
	}

	/* sanity check that partition doesn't extend beyond the namespace */
	if (!check_range(vns->host_lba_offset, vns->ns_size, host_ns_size)) {
		_WARN(vctrl, "NS/create: host namespace size mismatch\n");
		goto error;
	}

	/* check if namespace is readonly*/
	if (!vns->readonly)
		vns->readonly = get_disk_ro(host_ns->disk);

	vns->noiob = host_ns->noiob;
	if (vns->noiob != 0) {
		u64 tmp = vns->host_lba_offset;

		if (do_div(tmp, vns->noiob)) {
			_WARN(vctrl,
			      "NS/create: host partition is not aligned on host optimum IO boundary, performance might suffer");
			vns->noiob = 0;
		}
	}
	return;
error:
	vns->ns_size = 0;
}

/* Open new reference to a host namespace */
int nvme_mdev_vns_open(struct nvme_mdev_vctrl *vctrl,
		       u32 host_nsid, unsigned int host_partid)
{
	struct nvme_mdev_vns *vns;
	u32 user_nsid;
	int ret;

	_INFO(vctrl, "open host_namespace=%u, partition=%u\n",
	      host_nsid, host_partid);

	mutex_lock(&vctrl->lock);
	ret = -ENODEV;
	if (nvme_mdev_vctrl_is_dead(vctrl))
		goto out;

	/* create the namespace object */
	ret = -ENOMEM;
	vns = kzalloc_node(sizeof(*vns), GFP_KERNEL, vctrl->hctrl->node);
	if (!vns)
		goto out;

	uuid_gen(&vns->uuid); // TODOLATER: NS: non random NS UUID
	vns->host_nsid = host_nsid;
	vns->host_partid = host_partid;

	/* find the host namespace */
	vns->host_ns = nvme_find_get_ns(vctrl->hctrl->nvme_ctrl, host_nsid);
	if (!vns->host_ns) {
		ret = -ENODEV;
		goto error1;
	}

	if (test_bit(NVME_NS_DEAD, &vns->host_ns->flags) ||
	    test_bit(NVME_NS_REMOVING, &vns->host_ns->flags) ||
	    !vns->host_ns->disk) {
		ret = -ENODEV;
		goto error2;
	}

	/* get the block device for the partition that we will use */
	// vns->host_part = bdget_disk(vns->host_ns->disk, host_partid);
	vns->host_part = xa_load(&vns->host_ns->disk->part_tbl, host_partid);

	if (!vns->host_part) {
		ret = -ENODEV;
		goto error2;
	}

	/* get exclusive access to the block device (partition) */
	vns->fmode = FMODE_READ | FMODE_EXCL;
	if (!vns->readonly)
		vns->fmode |= FMODE_WRITE;

	// ret = blkdev_get(vns->host_part, vns->fmode, vns);
	// 之前这里的代码函数删了 改成这样的
	ret = blkdev_get_by_dev(vns->host_part->bd_dev, vns->fmode, vns);

	if (ret)
		goto error2;

	/* read properties of the host namespace */
	nvme_mdev_vns_read_host_properties(vctrl, vns, vns->host_ns);

	/* Allocate a user namespace ID for this namespace */
	ret = -ENOSPC;
	for (user_nsid = 1; user_nsid <= MAX_VIRTUAL_NAMESPACES; user_nsid++)
		if (!nvme_mdev_vns_from_vnsid(vctrl, user_nsid))
			break;

	if (user_nsid > MAX_VIRTUAL_NAMESPACES)
		goto error3;

	nvme_mdev_io_pause(vctrl);

	vctrl->namespaces[user_nsid - 1] = vns;
	vns->nsid = user_nsid;

	/* Announce the new namespace to the user */
	nvme_mdev_vns_send_event(vctrl, user_nsid);
	nvme_mdev_io_resume(vctrl);
	ret = 0;
	goto out;
error3:
	blkdev_put(vns->host_part, vns->fmode);
error2:
	nvme_put_ns(vns->host_ns);
error1:
	kfree(vns);
out:
	mutex_unlock(&vctrl->lock);
	return ret;
}

/* Re-open new reference to a host namespace, after notification
 * of change in the host namespace
 */
static bool nvme_mdev_vns_reopen(struct nvme_mdev_vctrl *vctrl,
				 struct nvme_mdev_vns *vns)
{
	struct nvme_ns *host_ns;

	lockdep_assert_held(&vctrl->lock);

	_INFO(vctrl, "reopen host namespace %u, partition=%u\n",
	      vns->host_nsid, vns->host_partid);

	/* namespace disappeared on the host - invalid*/
	host_ns = nvme_find_get_ns(vctrl->hctrl->nvme_ctrl, vns->host_nsid);
	if (!host_ns)
		return false;

	/* different namespace with same ID on the host - invalid*/
	if (vns->host_ns != host_ns)
		goto error1;

	// basic checks on the namespace
	if (test_bit(NVME_NS_DEAD, &host_ns->flags) ||
	    test_bit(NVME_NS_REMOVING, &host_ns->flags) ||
	    !host_ns->disk)
		goto error1;

	/* read properties of the host namespace */
	nvme_mdev_io_pause(vctrl);
	nvme_mdev_vns_read_host_properties(vctrl, vns, host_ns);
	nvme_mdev_io_resume(vctrl);

	nvme_put_ns(host_ns);
	return true;
error1:
	nvme_put_ns(host_ns);
	return false;
}

/* Destroy a virtual namespace*/
static int __nvme_mdev_vns_destroy(struct nvme_mdev_vctrl *vctrl, u32 user_nsid)
{
	struct nvme_mdev_vns *vns;

	lockdep_assert_held(&vctrl->lock);

	vns = nvme_mdev_vns_from_vnsid(vctrl, user_nsid);
	if (!vns)
		return -ENODEV;

	nvme_mdev_vns_send_event(vctrl, user_nsid);
	nvme_mdev_io_pause(vctrl);

	vctrl->namespaces[user_nsid - 1] = NULL;
	blkdev_put(vns->host_part, vns->fmode);
	nvme_put_ns(vns->host_ns);
	kfree(vns);
	nvme_mdev_io_resume(vctrl);
	return 0;
}

/* Destroy a virtual namespace (external interface) */
int nvme_mdev_vns_destroy(struct nvme_mdev_vctrl *vctrl, u32 user_nsid)
{
	int ret;

	mutex_lock(&vctrl->lock);
	nvme_mdev_io_pause(vctrl);
	ret = __nvme_mdev_vns_destroy(vctrl, user_nsid);
	nvme_mdev_io_resume(vctrl);
	mutex_unlock(&vctrl->lock);

	return ret;
}

/* Destroy all virtual namespaces */
void nvme_mdev_vns_destroy_all(struct nvme_mdev_vctrl *vctrl)
{
	u32 user_nsid;

	lockdep_assert_held(&vctrl->lock);

	for (user_nsid = 1 ; user_nsid <= MAX_VIRTUAL_NAMESPACES ; user_nsid++)
		__nvme_mdev_vns_destroy(vctrl, user_nsid);
}

/* Get a virtual namespace */
struct nvme_mdev_vns *nvme_mdev_vns_from_vnsid(struct nvme_mdev_vctrl *vctrl,
					       u32 user_ns_id)
{
	if (user_ns_id == 0 || user_ns_id > MAX_VIRTUAL_NAMESPACES)
		return NULL;
	return vctrl->namespaces[user_ns_id - 1];
}

/* Print description off all virtual namespaces */
int nvme_mdev_vns_print_description(struct nvme_mdev_vctrl *vctrl,
				    char *buf, unsigned int size)
{
	int nsid, ret = 0;

	mutex_lock(&vctrl->lock);

	for (nsid = 1; nsid <= MAX_VIRTUAL_NAMESPACES; nsid++) {
		int n;
		struct nvme_mdev_vns *vns = nvme_mdev_vns_from_vnsid(vctrl,
				nsid);
		if (!vns)
			continue;

		else if (vns->host_partid == 0)
			n = snprintf(buf, size, "VNS%d: nvme%dn%d\n",
				     nsid, vctrl->hctrl->id,
				     (int)vns->host_nsid);
		else
			n = snprintf(buf, size, "VNS%d: nvme%dn%dp%d\n",
				     nsid, vctrl->hctrl->id,
				     (int)vns->host_nsid,
				     (int)vns->host_partid);
		if (n > size)
			return -ENOMEM;
		buf += n;
		size -= n;
		ret += n;
	}
	mutex_unlock(&vctrl->lock);
	return ret;
}

/* Processes an update on the host namespace */
void nvme_mdev_vns_host_ns_update(struct nvme_mdev_vctrl *vctrl,
				  u32 host_nsid, bool removed)
{
	int nsid;

	mutex_lock(&vctrl->lock);

	for (nsid = 1; nsid <= MAX_VIRTUAL_NAMESPACES; nsid++) {
		struct nvme_mdev_vns *vns = nvme_mdev_vns_from_vnsid(vctrl,
								     nsid);
		if (!vns || vns->host_nsid != host_nsid)
			continue;

		if (removed || !nvme_mdev_vns_reopen(vctrl, vns))
			__nvme_mdev_vns_destroy(vctrl, nsid);
		else
			nvme_mdev_vns_send_event(vctrl, nsid);
	}
	mutex_unlock(&vctrl->lock);
}
