// SPDX-License-Identifier: GPL-2.0+
/*
 * NVMe parent (host) device abstraction
 * Copyright (c) 2019 - Maxim Levitsky
 */
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/nvme.h>
#include <linux/module.h>
#include <linux/mdev.h>
#include <asm/div64.h>
#include "priv.h"

/* IO schd */
#include "../host/nvme.h"
#include <linux/random.h>
#include <linux/kthread.h>
#include <linux/sort.h>
#include <linux/delay.h>

#define DEBUG	1
#define SCHD_SHUFFLE_INTERVAL 10
#define CMDS_BUCKET_SIZE 1500

static LIST_HEAD(nvme_mdev_hctrl_list);
static DEFINE_MUTEX(nvme_mdev_hctrl_list_mutex);
static struct nvme_mdev_inst_type **instance_types;

unsigned int io_timeout_ms = 30000;
module_param_named(io_timeout, io_timeout_ms, uint, 0644);
MODULE_PARM_DESC(io_timeout,
		 "Maximum I/O command completion timeout (in msec)");

unsigned int poll_timeout_ms = 500;
// unsigned int poll_timeout_ms = 0;
module_param_named(poll_timeout, poll_timeout_ms, uint, 0644);
MODULE_PARM_DESC(poll_timeout,
		 "Maximum idle time to keep polling (in msec) (0 - poll forever)");

unsigned int admin_poll_rate_ms = 100;
module_param_named(admin_poll_rate, poll_timeout_ms, uint, 0644);
MODULE_PARM_DESC(admin_poll_rate,
		 "Admin queue polling rate (in msec) (used only when shadow doorbell is disabled)");

bool use_shadow_doorbell = true;
module_param(use_shadow_doorbell, bool, 0644);
MODULE_PARM_DESC(use_shadow_doorbell,
		 "Enable the shadow doorbell NVMe extension");

/* IO schd */
unsigned int mdev_device_num = 1;
module_param(mdev_device_num, uint, 0644);
MODULE_PARM_DESC(mdev_device_num,
		 "Maximam number of mdev devices to create");

unsigned int total_threshold = 40;
module_param(total_threshold, uint, 0644);
MODULE_PARM_DESC(total_threshold,
		 "Threshold for the IO throttling for throughput-intensive worklaods");

struct nvme_mdev_scheduler *schd;
struct task_struct *tsk;
struct task_struct *data_tsk;
int schd_period = 200;

unsigned long long cmds_started_cycles[1000];
unsigned long long cmds_complete_cycles[1000];

static void schd_handle_work(void);
static void schd_count_work(void);

/* Create a new host controller */
static struct nvme_mdev_hctrl *nvme_mdev_hctrl_create(struct nvme_ctrl *ctrl)
{
	struct nvme_mdev_hctrl *hctrl;
	u32 max_lba_transfer;
	unsigned int nr_host_queues;

	/* TODOLATER: IO: support more page size configurations*/
	if (ctrl->page_size != PAGE_SIZE) {
		dev_info(ctrl->dev, "no support for mdev - page_size mismatch");
		return NULL;
	}

	nr_host_queues = ctrl->ops->ext_queues_available(ctrl);
	max_lba_transfer = ctrl->max_hw_sectors >> (PAGE_SHIFT - 9);

	if (nr_host_queues == 0) {
		dev_info(ctrl->dev,
			 "no support for mdev - no mdev reserved queues available");
		return NULL;
	}

	hctrl = kzalloc_node(sizeof(*hctrl), GFP_KERNEL,
			     dev_to_node(ctrl->dev));
	if (!hctrl)
		return NULL;

	kref_init(&hctrl->ref);
	mutex_init(&hctrl->lock);

	hctrl->nvme_ctrl = ctrl;
	nvme_get_ctrl(ctrl);

	hctrl->oncs = ctrl->oncs &
		(NVME_CTRL_ONCS_DSM | NVME_CTRL_ONCS_WRITE_ZEROES);

	hctrl->id = ctrl->instance;
	hctrl->node = dev_to_node(ctrl->dev);
	hctrl->mdts = ilog2(__rounddown_pow_of_two(max_lba_transfer));
	hctrl->nr_host_queues = nr_host_queues;
	hctrl->total_host_queues = ctrl->ops->ext_queues_total(ctrl);

	mutex_lock(&nvme_mdev_hctrl_list_mutex);

	dev_info(ctrl->dev,
		 "mediated nvme support enabled, using up to %d host queues\n",
		 hctrl->nr_host_queues);

	list_add_tail(&hctrl->link, &nvme_mdev_hctrl_list);

	mutex_unlock(&nvme_mdev_hctrl_list_mutex);

	/* IO schd */
	hwq_init(ctrl);
	pr_info("IO schd: total hwqs %d.\n", schd->total_hwqs);

	if (mdev_register_device(ctrl->dev, &mdev_fops) < 0) {
		nvme_put_ctrl(ctrl);
		kfree(hctrl);
		return NULL;
	}
	return hctrl;
}

/* Release an unused host controller*/
static void nvme_mdev_hctrl_free(struct kref *ref)
{
	struct nvme_mdev_hctrl *hctrl =
		container_of(ref, struct nvme_mdev_hctrl, ref);

	dev_info(hctrl->nvme_ctrl->dev, "mediated nvme support disabled");

	nvme_put_ctrl(hctrl->nvme_ctrl);
	hctrl->nvme_ctrl = NULL;
	kfree(hctrl);
}

/* Lookup a host controller based on mdev parent device*/
struct nvme_mdev_hctrl *nvme_mdev_hctrl_lookup_get(struct device *parent)
{
	struct nvme_mdev_hctrl *hctrl = NULL, *tmp;

	mutex_lock(&nvme_mdev_hctrl_list_mutex);
	list_for_each_entry(tmp, &nvme_mdev_hctrl_list, link) {
		if (tmp->nvme_ctrl->dev == parent) {
			hctrl = tmp;
			kref_get(&hctrl->ref);
			break;
		}
	}
	mutex_unlock(&nvme_mdev_hctrl_list_mutex);
	return hctrl;
}

/* Release a held reference to a host controller*/
void nvme_mdev_hctrl_put(struct nvme_mdev_hctrl *hctrl)
{
	kref_put(&hctrl->ref, nvme_mdev_hctrl_free);
}

/* Destroy a host controller. It might still be kept in zombie state
 * if someone uses a reference to it
 */
static void nvme_mdev_hctrl_destroy(struct nvme_mdev_hctrl *hctrl)
{
	mutex_lock(&nvme_mdev_hctrl_list_mutex);
	list_del(&hctrl->link);
	mutex_unlock(&nvme_mdev_hctrl_list_mutex);

	hctrl->removing = true;
	mdev_unregister_device(hctrl->nvme_ctrl->dev);
	nvme_mdev_hctrl_put(hctrl);
}

/* Check how many host queues are still available */
int nvme_mdev_hctrl_hqs_available(struct nvme_mdev_hctrl *hctrl)
{
	int ret;

	mutex_lock(&hctrl->lock);
	ret =  hctrl->nr_host_queues;
	mutex_unlock(&hctrl->lock);
	return ret;
}

/* Reserve N host IO queues, for later allocation to a specific user*/
bool nvme_mdev_hctrl_hqs_reserve(struct nvme_mdev_hctrl *hctrl,
				 unsigned int n)
{
	mutex_lock(&hctrl->lock);

	if (hctrl->nr_host_queues == 0) {
		mutex_unlock(&hctrl->lock);
		return false;
	}
	else if (n < hctrl->nr_host_queues) {
		hctrl->nr_host_queues -= n;
	}
	else {
		hctrl->nr_host_queues = 0;
	}
	mutex_unlock(&hctrl->lock);
	return true;
}

/* Free N host IO queues, for allocation for other users*/
void nvme_mdev_hctrl_hqs_unreserve(struct nvme_mdev_hctrl *hctrl,
				   unsigned int n)
{
	mutex_lock(&hctrl->lock);
	hctrl->nr_host_queues += n;
	mutex_unlock(&hctrl->lock);
}

/* Allocate a host IO queue */
int nvme_mdev_hctrl_hq_alloc(struct nvme_mdev_hctrl *hctrl)
{
	u16 qid = 0;
	int ret = hctrl->nvme_ctrl->ops->ext_queue_alloc(hctrl->nvme_ctrl,
			&qid);

	if (ret)
		return ret;
	return qid;
}

/* Free an host IO queue */
void nvme_mdev_hctrl_hq_free(struct nvme_mdev_hctrl *hctrl, u16 qid)
{
	hctrl->nvme_ctrl->ops->ext_queue_free(hctrl->nvme_ctrl, qid);
}

/* Check if we can submit another IO passthrough command */
bool nvme_mdev_hctrl_hq_can_submit(struct nvme_mdev_hctrl *hctrl, u16 qid)
{
	return hctrl->nvme_ctrl->ops->ext_queue_full(hctrl->nvme_ctrl, qid);
}

/* Check if IO passthrough is supported for given IO optcode */
bool nvme_mdev_hctrl_hq_check_op(struct nvme_mdev_hctrl *hctrl, u8 optcode)
{
	switch (optcode) {
	case nvme_cmd_flush:
	case nvme_cmd_read:
	case nvme_cmd_write:
		/* these are mandatory*/
		return true;
	case nvme_cmd_write_zeroes:
		return (hctrl->oncs & NVME_CTRL_ONCS_WRITE_ZEROES);
	case nvme_cmd_dsm:
		return (hctrl->oncs & NVME_CTRL_ONCS_DSM);
	default:
		return false;
	}
}

/* Submit a IO passthrough command */
int nvme_mdev_hctrl_hq_submit(struct nvme_mdev_hctrl *hctrl,
			      u16 qid, u64 tag,
			      struct nvme_command *cmd,
			      struct nvme_ext_data_iter *datait)
{
	struct nvme_ctrl *ctrl = hctrl->nvme_ctrl;

	return ctrl->ops->ext_queue_submit(ctrl, qid, tag, cmd, datait);
}

/* Poll for completion of IO passthrough commands */
int nvme_mdev_hctrl_hq_poll(struct nvme_mdev_hctrl *hctrl,
			    u32 qid,
			    struct nvme_ext_cmd_result *results,
			    unsigned int max_len)
{
	struct nvme_ctrl *ctrl = hctrl->nvme_ctrl;

	return ctrl->ops->ext_queue_poll(ctrl, qid, results, max_len);
}

/* Destroy all host controllers */
void nvme_mdev_hctrl_destroy_all(void)
{
	struct nvme_mdev_hctrl *hctrl = NULL, *tmp;

	list_for_each_entry_safe(hctrl, tmp, &nvme_mdev_hctrl_list, link) {
		list_del(&hctrl->link);
		hctrl->removing = true;
		mdev_unregister_device(hctrl->nvme_ctrl->dev);
		nvme_mdev_hctrl_put(hctrl);
	}
}

/* Get the mdev instance given it sysfs name */
struct nvme_mdev_inst_type *nvme_mdev_inst_type_get(const char *name)
{
	int i;

	for (i = 0; instance_types[i]; i++) {
		const char *test =
			name + strlen(name) - strlen(instance_types[i]->name);

		if (strcmp(instance_types[i]->name, test) == 0)
			return instance_types[i];
	}
	return NULL;
}

/* This shows name of the instance type */
static ssize_t name_show(struct mdev_type *mtype,
			       struct mdev_type_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", mtype->kobj.name);
}
static MDEV_TYPE_ATTR_RO(name);

/* This shows description of the instance type */
static ssize_t description_show(struct mdev_type *mtype,
			       struct mdev_type_attribute *attr, char *buf)
{
	struct nvme_mdev_inst_type *type = nvme_mdev_inst_type_get(mtype->kobj.name);

	return sprintf(buf,
		       "MDEV nvme device, using maximum %d hw submission queues\n",
		       type->max_hw_queues);
}
static MDEV_TYPE_ATTR_RO(description);

/* This shows the device API of the instance type */
static ssize_t device_api_show(struct mdev_type *mtype,
			       struct mdev_type_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", VFIO_DEVICE_API_PCI_STRING);
}
static MDEV_TYPE_ATTR_RO(device_api);

/* This shows how many instances of this instance type can be created  */
// static ssize_t available_instances_show(struct kobject *kobj,
// 					struct device *dev, char *buf)
static ssize_t available_instances_show(struct mdev_type *mtype,
			       struct mdev_type_attribute *attr, char *buf)
{
	struct nvme_mdev_inst_type *type = nvme_mdev_inst_type_get(mtype->kobj.name);
	struct nvme_mdev_hctrl *hctrl = nvme_mdev_hctrl_lookup_get(mtype->parent->dev);
	int count;

	if (!hctrl)
		return -ENODEV;

	count = nvme_mdev_hctrl_hqs_available(hctrl);
	do_div(count, type->max_hw_queues);

	nvme_mdev_hctrl_put(hctrl);
	return sprintf(buf, "%d\n", count);
}
static MDEV_TYPE_ATTR_RO(available_instances);

static struct attribute *nvme_mdev_types_attrs[] = {
	&mdev_type_attr_name.attr,
	&mdev_type_attr_description.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_available_instances.attr,
	NULL,
};

/* Undo the creation of mdev array of instance types */
static void nvme_mdev_instance_types_fini(struct mdev_parent_ops *ops)
{
	int i;

	for (i = 0; instance_types[i]; i++) {
		struct nvme_mdev_inst_type *type = instance_types[i];

		kfree(type->attrgroup);
		kfree(type);
	}

	kfree(instance_types);
	instance_types = NULL;

	kfree(ops->supported_type_groups);
	ops->supported_type_groups = NULL;
}

/* Create the array of mdev instance types from our array of them */
static int nvme_mdev_instance_types_init(struct mdev_parent_ops *ops)
{
	unsigned int i;
	struct nvme_mdev_inst_type *type;
	struct attribute_group *attrgroup;

	ops->supported_type_groups = kzalloc(sizeof(struct attribute_group *)
			* (MAX_HOST_QUEUES + 1), GFP_KERNEL);

	if (!ops->supported_type_groups)
		return -ENOMEM;

	instance_types = kzalloc(sizeof(struct nvme_mdev_inst_type *)
			* MAX_HOST_QUEUES + 1, GFP_KERNEL);

	if (!instance_types) {
		kfree(ops->supported_type_groups);
		ops->supported_type_groups = NULL;
		return -ENOMEM;
	}

	for (i = 0; i < MAX_HOST_QUEUES; i++) {
		type = kzalloc(sizeof(*type), GFP_KERNEL);
		if (!type) {
			nvme_mdev_instance_types_fini(ops);
			return -ENOMEM;
		}
		snprintf(type->name, sizeof(type->name), "%dQ_V1", i + 1);
		type->max_hw_queues = i + 1;

		attrgroup = kzalloc(sizeof(*attrgroup), GFP_KERNEL);
		if (!attrgroup) {
			kfree(type);
			nvme_mdev_instance_types_fini(ops);
			return -ENOMEM;
		}

		attrgroup->attrs = nvme_mdev_types_attrs;
		attrgroup->name = type->name;
		type->attrgroup = attrgroup;
		instance_types[i] = type;
		ops->supported_type_groups[i] = attrgroup;
	}
	return 0;
}

/* Updates in host controller state*/
static void nvme_mdev_nvme_ctrl_state_changed(struct nvme_ctrl *ctrl)
{
	struct nvme_mdev_hctrl *hctrl = nvme_mdev_hctrl_lookup_get(ctrl->dev);
	struct nvme_mdev_vctrl *vctrl;

	switch (ctrl->state) {
	case NVME_CTRL_NEW:
		/* do nothing as new controller is not yet initialized*/
		break;

	case NVME_CTRL_LIVE:
		/* new controller is live, create a mdev for it*/
		if (!hctrl) {
			hctrl = nvme_mdev_hctrl_create(ctrl);
			return;
		/* a controller is live again after reset/reconnect/suspend*/
		} else {
			mutex_lock(&nvme_mdev_vctrl_list_mutex);
			list_for_each_entry(vctrl, &nvme_mdev_vctrl_list, link)
				if (vctrl->hctrl == hctrl)
					nvme_mdev_vctrl_resume(vctrl);
			mutex_unlock(&nvme_mdev_vctrl_list_mutex);
		}
		break;

	case NVME_CTRL_RESETTING:
	case NVME_CTRL_CONNECTING:
	case NVME_CTRL_SUSPENDED:
		/* controller is temporarily not usable, stop using its queues*/
		if (!hctrl)
			return;

		mutex_lock(&nvme_mdev_vctrl_list_mutex);
		list_for_each_entry(vctrl, &nvme_mdev_vctrl_list, link)
			if (vctrl->hctrl == hctrl)
				nvme_mdev_vctrl_pause(vctrl);
		mutex_unlock(&nvme_mdev_vctrl_list_mutex);
		break;

	case NVME_CTRL_DELETING:
	case NVME_CTRL_DEAD:
	// case NVME_CTRL_ADMIN_ONLY:
		/* host nvme controller is dead, remove it*/
		if (!hctrl)
			return;
		nvme_mdev_hctrl_destroy(hctrl);
		break;
	}

	if (hctrl)
		nvme_mdev_hctrl_put(hctrl);
}

/* A host namespace might have its properties changed/removed.*/
static void nvme_mdev_nvme_ctrl_ns_updated(struct nvme_ctrl *ctrl,
					   u32 nsid, bool removed)
{
	struct nvme_mdev_vctrl *vctrl;
	struct nvme_mdev_hctrl *hctrl = nvme_mdev_hctrl_lookup_get(ctrl->dev);

	if (!hctrl)
		return;

	mutex_lock(&nvme_mdev_vctrl_list_mutex);
	list_for_each_entry(vctrl, &nvme_mdev_vctrl_list, link)
		if (vctrl->hctrl == hctrl)
			nvme_mdev_vns_host_ns_update(vctrl, nsid, removed);
	mutex_unlock(&nvme_mdev_vctrl_list_mutex);
	nvme_mdev_hctrl_put(hctrl);
}

static struct nvme_mdev_driver nvme_mdev_driver = {
	.owner = THIS_MODULE,
	.nvme_ctrl_state_changed = nvme_mdev_nvme_ctrl_state_changed,
	.nvme_ns_state_changed = nvme_mdev_nvme_ctrl_ns_updated,
};

/* IO schd */
void hwq_init(struct nvme_ctrl *ctrl)
{
	int ret = 0;
	u16 qid = 0;
	struct nvme_mdev_hq *hq = NULL;

	while (!ret) {
		ret = ctrl->ops->ext_queue_alloc(ctrl, &qid);
        if (ret)
        	return;
        
        hq = kzalloc_node(sizeof(*hq), GFP_KERNEL, dev_to_node(ctrl->dev));

		if (!hq) {
			ctrl->ops->ext_queue_free(ctrl, qid);
			return;
		}

		hq->hqid = qid;
		hq->usecount = 0;
		hq->bound = false;
		schd->host_hw_queues[schd->total_hwqs] = hq;
		schd->total_hwqs++;
	}
}

static void schd_init(void)
{
	int i;
	if (!schd) {
		schd = kzalloc(sizeof(struct nvme_mdev_scheduler), GFP_KERNEL);
		schd->clients = kzalloc(sizeof(struct nvme_mdev_client *) * MAX_VDEV, GFP_KERNEL);
		schd->qos_ddl_client = kzalloc(sizeof(struct nvme_mdev_client *), GFP_KERNEL);
		schd->max_clients = MAX_VDEV;
		schd->in_schd = false;
		schd->need_schd = false;
		schd->nr_used_hwqs = mdev_device_num;
		schd->mdev_device_num = mdev_device_num;
		schd->active_mdev_dev_num = mdev_device_num;
		schd->start_index = 0;
		schd->total_hwqs = 0;
		schd->qos_ddl_client->vctrl = NULL;
		schd->total_threshold = total_threshold;
		schd->threshold = total_threshold;
		schd->thread_parked = false;
		pr_info("host.c: init schd with %d maximum mdev devices.\n", schd->mdev_device_num);
		pr_info("host.c: init schd with %d threshold.\n", schd->threshold);

		mutex_init(&schd->lock);
		for (i = 0; i < schd->max_clients; i++){
			schd->clients[i] = kzalloc(sizeof(struct nvme_mdev_client), GFP_KERNEL);
			schd->clients[i]->workloads = schd->clients[i]->v_workloads = 0;
		}
		schd->cq_num = 0;
		schd->curr_client = -1;
	}
}  

static void schd_remove(void)
{
	if (tsk) {
		kthread_stop(tsk);
		kfree(tsk);
		tsk = NULL;
	}
	
	if (data_tsk) {
		kthread_stop(data_tsk);
		kfree(data_tsk);
		data_tsk == NULL;
	}

	int i = 0;
	if (schd) {
		for (i = 0; i < schd->max_clients; i++) {
			kfree(schd->clients[i]);
		}
		kfree(schd->clients);
		kfree(schd);
	}
}

static void schd_print_info(void)
{
	int i = 0;
	struct nvme_vcq *vcq;

	// if (schd && schd->total_hwqs > 0) {
	// 	for (i = 0; i< schd->total_hwqs; i++) {
	// 		pr_info("host.c: hwqid %d.\n", schd->host_hw_queues[i]->hqid);
	// 	}
	// }
	pr_info("host.c: one period.\n");
	if (schd && schd->curr_client >= 0) {
		pr_info("IO schd: %d cqs in scheduling.\n", schd->cq_num);
		for (i = 0; i < schd->cq_num; i++){
			vcq = schd->cqp[i];
			pr_info("IO schd: clientid %d vcq_id %d vsq_id %d hwq %d hold_workload %d reserve workload %d.\n", 
				schd->clients[vcq->vctrl_id]->vctrl->id, 
				vcq->qid, 
				vcq->vsq->qid, 
				vcq->vsq->hsq, 
				vcq->workload + 
				nvme_mdev_vctrl_hold_workload(vcq->vsq), 
				nvme_mdev_vctrl_reserved_workload(vcq->vsq));
		}
	}
}

int schd_add_vctrl(struct nvme_mdev_vctrl *vctrl)
{
	if(schd->curr_client > schd->max_clients) {
		pr_err("nvme mdev schd: exceed schedule limitation!\n");
		return -EINVAL;
	}

	mutex_lock(&schd->lock);
	schd->clients[++schd->curr_client]->vctrl = vctrl;
	vctrl->id = schd->curr_client;
	if(vctrl->type == QOS_DDL)
		schd->qos_ddl_client->vctrl = vctrl;
	mutex_unlock(&schd->lock);

	return schd->curr_client;
}

int schd_remove_vctrl(struct nvme_mdev_vctrl *vctrl)
{
	if (schd->curr_client >= 0) {
		pr_info("nvme mdev schd: remove vctrl from scheduler\n");
		mutex_lock(&schd->lock);
		schd->curr_client--;
		mutex_unlock(&schd->lock);
	}
	return schd->curr_client;
}

void schd_remove_cq(struct nvme_mdev_vctrl *vctrl, u16 qid)
{
	int i = 0, j = -1;
	struct nvme_vcq *vcq;

	lockdep_assert_held(&schd->lock);
	// mutex_lock(&schd->lock);
	for (i = 0; i < schd->cq_num; i++) {
		vcq = schd->cqp[i];
		if (vcq->qid == qid && vctrl->id == schd->clients[vcq->vctrl_id]->vctrl->id) {
			schd->cq_num--;
			j = i;
			break;
		}
	}
	if (j > -1) {
		for (i = j; i < schd->cq_num; i++) {
			schd->cqp[i] = schd->cqp[i + 1];
		}
	}
	// mutex_unlock(&schd->lock);
}

void schd_remove_hwq(u16 qid)
{
	int i = 0, j = -1;
	struct nvme_mdev_hq *hq;
	for (i = 0; i < schd->nr_used_hwqs; i++) {
		hq = schd->host_hw_queues[i];
		if (hq->hqid == qid) {
			schd->nr_used_hwqs--;
			j = i;
			break;
		}
	}
	if (j > -1) {
		for (i = j; i < schd->nr_used_hwqs; i++) {
			schd->host_hw_queues[i] = schd->host_hw_queues[i + 1];
		}
	}
}

int schd_get_hwq(u16 qid)
{
	int i = 0;
	for (i = 0; i < schd->nr_used_hwqs; i++) {
		if (schd->host_hw_queues[i]->hqid == qid) {
			return i;
		}
	}
	return -1;
}

/* workloads written into vsq before it is scheduled */
int nvme_mdev_vctrl_reserved_workload(struct nvme_vsq *vsq){
	struct nvme_vcq *vcq = vsq->vcq;
	int workloads = vsq->head >= vcq->tail ? (vsq->head - vcq->tail) : (vsq->size - vcq->tail + vsq->head);
	if (workloads != 0)
		pr_info("IO schd: vclient %d vsq %d reserve workloads %d vsq head %d vcq tail %d.\n", vsq->vctrl_id, vsq->qid, workloads, vsq->head, vcq->tail);
	return workloads;
}

/* the realtime workloads that are writen into vsq by the guest */
int nvme_mdev_vctrl_hold_workload(struct nvme_vsq *vsq){
	struct nvme_vcq *vcq = vsq->vcq;
	u16 sq_tail = le32_to_cpu(schd->clients[vsq->vctrl_id]->vctrl->mmio.dbs[vsq->qid].sqt);
	return sq_tail >= vcq->tail ? (sq_tail - vcq->tail) : (vsq->size - vcq->tail + sq_tail);
}

cycles_t calcDeltaCycles(struct nvme_mdev_perf *perf, struct nvme_mdev_perf *last_perf)
{
	cycles_t cycles = perf->cycles_send_to_hw + perf->cycles_receive_from_hw + perf->cycles_irq_delivery;
	cycles_t last_cycles = last_perf->cycles_send_to_hw + last_perf->cycles_receive_from_hw + last_perf->cycles_irq_delivery;

	return (cycles - last_cycles);
}

unsigned long long calcDeltaCmds(struct nvme_mdev_perf *perf, struct nvme_mdev_perf *last_perf)
{
	return (perf->cmds_complete - last_perf->cmds_complete);
}

int nvme_mdev_vctrl_update_workload(struct nvme_mdev_client *vclt){

	int sq_id;
	struct nvme_mdev_vctrl *vctrl = vclt->vctrl;
	struct nvme_vsq *vsq;
    struct nvme_vcq *vcq;

    unsigned int qos_type = vctrl->type;
    unsigned int target = vctrl->qos_val;
    // struct nvme_mdev_perf *perf = &vctrl->perf;
	// struct nvme_mdev_perf *last_perf = &vctrl->last_perf;
    // cycles_t deltaCycles = calcDeltaCycles(perf, last_perf);
    // u64 tmp = 200;
    // pr_info("host.c: update workload for %d vclient, deltaCycles: %llu\n", vctrl->id, deltaCycles);

	/* Adaptive LP */
	unsigned int vctrl_total_workload = 0;

    sq_id = 1;
	// mutex_lock(&vctrl->lock);
	for_each_set_bit_from(sq_id, vctrl->vsq_en, MAX_VIRTUAL_QUEUES){
		vsq = &vctrl->vsqs[sq_id];
		vcq = vsq->vcq;
		vcq->workload = (vcq->real_phase - vcq->last_phase) * vcq->size + vcq->head - vcq->last_head;
		vctrl_total_workload += vcq->workload;

		switch (qos_type)
		{
			case QOS_TPT: {
			    vcq->weight = vcq->workload;
				// vcq->weight = 0;
				break;
			}
			case QOS_LAT: {
				// do_div(tmp, calcDeltaCmds(perf, last_perf));
				// vcq->weight = tmp;	
				vcq->weight = vcq->workload;
				break;
			}
			case QOS_DDL: {
				vcq->workload = INT_MAX - sq_id;
				break;
			}
			default: {
				break;
			}
		}
	    vcq->last_head = vcq->head;
		vcq->last_phase = vcq->real_phase;
		// pr_info("%d: workloads: %llu\n", sq_id, vcq->workload);

		/*
		vcq = vsq->vcq;
		vcq->workload = (vcq->real_phase - vcq->last_phase) * vcq->size + vcq->head - vcq->last_head ;
		vcq->last_head = vcq->head;
		vcq->last_phase = vcq->real_phase;
		*/
	}
	vctrl->last_perf = vctrl->perf;
	// pr_info("host.c: after update\n");
	// mutex_unlock(&vctrl->lock);

	/* Adaptive LP: this vctrl has no workloads in this period. */
	if (qos_type == QOS_TPT && vctrl_total_workload > 0) {
		return 1;
	}
	else {
		return 0;
	}		
}

/* compare weights of two virtual queues */
int queue_weight_cmp(const void *a, const void *b) {
	const struct nvme_vcq *cqa = *(const struct nvme_vcq **)a;
	const struct nvme_vcq *cqb = *(const struct nvme_vcq **)b;
	unsigned _aw = cqa->weight;
	unsigned _bw = cqb->weight;
	return (signed)_bw - (signed)_aw;
}

/* compare workloads of two virtual queues */
int queue_workload_cmp(const void *a, const void *b){
	const struct nvme_vcq *cqa = *(const struct nvme_vcq **)a;
	const struct nvme_vcq *cqb = *(const struct nvme_vcq **)b;
	unsigned _aw = cqa->workload + nvme_mdev_vctrl_hold_workload(cqa->vsq);
	unsigned _bw = cqb->workload + nvme_mdev_vctrl_hold_workload(cqb->vsq);
	return (signed)_bw - (signed)_aw;
}

void schd_sort_cqp(void){
	if(schd && schd->curr_client >=0 && schd->cq_num > 0)
		sort(&schd->cqp, schd->cq_num, sizeof(struct nvme_vcq *), queue_weight_cmp, NULL);
		// sort(&schd->cqp, schd->cq_num, sizeof(struct nvme_vcq *), queue_workload_cmp, NULL);
}

void schd_swap_cqp(struct nvme_vcq **a, struct nvme_vcq **b){
	struct nvme_vcq *tmp = *a;
	*a = *b;
	*b = tmp;
}

void schd_shuffle_cqp(void){
	char randnum;
	int i;
	for (i = 0; i < schd->cq_num; i++){
		get_random_bytes_arch(&randnum, 1);
		schd_swap_cqp(&schd->cqp[randnum % (schd->cq_num - i)], &schd->cqp[schd->cq_num - i - 1]);
	}
}

static int schd_thread(void *data)
{
	int time_count = 0;
    do {
    	time_count++;
    	schd->need_schd = true;
		if (kthread_should_park()) {
			pr_info("IO schd: schd thread parked\n");
			kthread_parkme();
			pr_info("IO schd: schd thread resume\n");
		}
		schd_handle_work();
		msleep(schd_period);
    } while (!kthread_should_stop());

    return time_count;
}

static int data_thread(void *data)
{
	int time_count = 0;
	do{
		time_count++;
		schd_count_work();
		msleep(2);
	} while (!kthread_should_stop());
	return time_count;
}

static void schd_handle_work(void)
{
	static int a = 0;
	int i = 0, k = 0;
	int total_cmds;
	unsigned long long total_time;
	int rounds;

	struct nvme_mdev_client *vclient;
	struct nvme_mdev_vctrl *vctrl;
	struct nvme_mdev_vctrl *hq_vctrl = NULL;
	struct nvme_vsq *vsq;
	struct nvme_vcq *vcq;
	struct nvme_mdev_hq *hq;
	struct nvme_mdev_perf_data *perf_data;

	a++;
	
	unsigned int active_dev_num = 0;
	if(schd && schd->curr_client >= 0){
		mutex_lock(&schd->lock);
		for (i = 0; i <= schd->curr_client; i++){
			vclient = schd->clients[i];
			active_dev_num += nvme_mdev_vctrl_update_workload(vclient);
		}

		schd->active_mdev_dev_num = active_dev_num;
		
		if (schd->active_mdev_dev_num > 0)
			schd->threshold  = schd->total_threshold / schd->active_mdev_dev_num;
		else
			schd->threshold  = schd->total_threshold;


		

		schd_sort_cqp();

		if (schd->cq_num > schd->nr_used_hwqs) {

			for (i = 0; i < schd->cq_num; i++){
				vcq = schd->cqp[i];
				vsq = vcq->vsq;
				vctrl = schd->clients[vcq->vctrl_id]->vctrl;

				// mutex_lock(&vsq->lock);
				vsq->wait = true;
				// mutex_unlock(&vsq->lock);
			}
		}


		k = schd->mdev_device_num;

		for (i = 0; i < schd->cq_num; i++) {
			if (k > schd->nr_used_hwqs - 1)
				break;
			vcq = schd->cqp[i];
			vctrl = schd->clients[vcq->vctrl_id]->vctrl;
			vsq = vcq->vsq;
			hq = schd->host_hw_queues[k];
  
			if (vsq->wait) {
				// mutex_lock(&vsq->lock);
				if (vsq->hsq == hq->hqid) {
					k++;
				}
				else if (hq->vctrl_id == vctrl->id) {
					vsq->hsq = hq->hqid;
					k++;
				}
				else {
					hq_vctrl = schd->clients[hq->vctrl_id]->vctrl;
					// pr_info("%u -> %u.%u\n",  hq->hqid, vctrl->id, vsq->qid);
					mutex_lock(&schd->clients[hq->vctrl_id]->vctrl->lock);
					nvme_mdev_io_pause(schd->clients[hq->vctrl_id]->vctrl);
					mutex_lock(&hq_vctrl->host_hw_queues_lock);

					/* remove hwq from former vclient */
					list_del_init(&hq->link);
					mutex_unlock(&hq_vctrl->host_hw_queues_lock);
					nvme_mdev_io_resume(schd->clients[hq->vctrl_id]->vctrl);


					mutex_unlock(&schd->clients[hq->vctrl_id]->vctrl->lock);

					/* add hq to new vclient */
					mutex_lock(&vctrl->lock);
					nvme_mdev_io_pause(vctrl);
					mutex_lock(&vctrl->host_hw_queues_lock);

				    // hsqcnt = nvme_mdev_vctrl_hqs_list(vctrl, hsqs);

					list_add_tail(&hq->link, &vctrl->host_hw_queues);

					vsq->hsq = hq->hqid;
					vsq->assigned = true;
					k++;

					hq->vctrl_id = vctrl->id;
					mutex_unlock(&vctrl->host_hw_queues_lock);
					nvme_mdev_io_resume(vctrl);

					mutex_unlock(&vctrl->lock);
				}
				vsq->wait = false;
				// mutex_unlock(&vsq->lock);
			}	
		}

		/* bound left vq to bound hwq for every vctrl */
		i--;
	    for (; i < schd->cq_num; i++) {
			printk("bind left vq\n");
			vcq = schd->cqp[i];
        	vsq = vcq->vsq;
		 	// mutex_lock(&vsq->lock);
            mutex_lock(&vctrl->host_hw_queues_lock);
        	vctrl = schd->clients[vcq->vctrl_id]->vctrl;
			hq = schd->host_hw_queues[vctrl->id];
        	if (vsq->wait) {
				// mutex_lock(&vsq->lock);
				vsq->hsq = hq->hqid;
				vsq->wait = false;
				// mutex_unlock(&vsq->lock);
			}
			mutex_unlock(&vctrl->host_hw_queues_lock);
            // mutex_unlock(&vsq->lock);
		}

		/* clear start cmd count every schd peroid */
		for(i = 0; i <= schd->curr_client; i++) {
			vclient = schd->clients[i];
			vctrl = vclient->vctrl;
			vctrl->perf.cmds_started = 0;
		}
		
		mutex_unlock(&schd->lock);
	}
}




void hwq_fini(void)
{
	int i = 0;
	struct nvme_mdev_hq *hq = NULL;
	struct nvme_mdev_hctrl *hctrl = NULL, *tmp;

	list_for_each_entry_safe (hctrl, tmp, &nvme_mdev_hctrl_list, link) {
		for (i = 0; schd && i < schd->total_hwqs; i++) {
			hq = schd->host_hw_queues[i];
			nvme_mdev_hctrl_hq_free(hctrl, hq->hqid);
		}
	}
}


static void schd_count_work(void)
{
	int debug_flag = 0;
	int i, j, k, bucket_bound, cmds_accumulated; 
	int bucket_size, last_phase, rounds;
	int started_cmds_counted, complete_cmds_counted;
	int buckets[CMDS_BUCKET_SIZE], id_buckets[CMDS_BUCKET_SIZE];
	unsigned long long total_time;   /* ns */
	struct nvme_mdev_vctrl *vctrl = NULL;
	struct nvme_mdev_perf_data *perf_data = NULL;
	if(schd && schd->curr_client >= 0) {
		for(i = 0; i <= schd->curr_client; i++) {
			vctrl = schd->clients[i]->vctrl;
			if(vctrl->type != QOS_DDL)
				continue;
			perf_data = vctrl->perf_data;

			bucket_size = 0;
			started_cmds_counted = 0;
			complete_cmds_counted = 0;
			memset(buckets, 0, CMDS_BUCKET_SIZE * sizeof(int));
			// memset(id_buckets, 0, CMDS_BUCKET_SIZE * sizeof(int));
			// memset(cmds_complete_cycles, 0, 1000 * sizeof(unsigned long long));
			
			last_phase = perf_data->phase;
			rounds = perf_data->rounds;
			perf_data->phase = 1 - last_phase;
			
			if(perf_data->cmds_started[last_phase] <= 0){
				continue;
			}

			/* count how many cmdids are used */
			for (j = 0; j < perf_data->cmds_started[last_phase]; j++){
				if((int)perf_data->cmds_started_id[last_phase][j] < CMDS_BUCKET_SIZE){
					buckets[(int)perf_data->cmds_started_id[last_phase][j]] = 1;
				}	
				else{
					printk("host.c count thread: cmdid %d is used.\n", perf_data->cmds_started_id[last_phase][j]);
				}
			}

			/* record cmdids in a continuous array */
			for (j = 0; j < CMDS_BUCKET_SIZE; j++){
				if(buckets[j] == 1){
					id_buckets[bucket_size++] = j;
				}
			}

			/* use bucket array to record cmd number per cmdid */
			memset(buckets, 0, CMDS_BUCKET_SIZE * sizeof(int));
			cmds_accumulated = 0;
			bucket_bound = 0;
			for(j = 0; j < bucket_size; j++){
				if(j > 0) 
					bucket_bound += buckets[j - 1];
				cmds_accumulated = bucket_bound;
				for(k = 0; k < perf_data->cmds_started[last_phase]; k++) {
					if((int)perf_data->cmds_started_id[last_phase][k] == id_buckets[j]) {
						cmds_started_cycles[started_cmds_counted++] = 
						        	perf_data->cmds_started_cycles[last_phase][k];
						buckets[j]++;
					}
				}
				for(k = 0; k < perf_data->cmds_complete[last_phase]; k++) {
					if(perf_data->cmds_complete_id[last_phase][k] == id_buckets[j]) {
						/* Skip invalid data which comes from last round*/
						if(perf_data->cmds_complete_cycles[last_phase][k] <= cmds_started_cycles[bucket_bound]) {
							continue;
						}
						/* count valid cmds complete cycles */
						cmds_complete_cycles[cmds_accumulated++] = 
									perf_data->cmds_complete_cycles[last_phase][k];
					}
				}
			}
			
			/* cal avg cycles */
			cmds_accumulated = 0;
			total_time = 0;
			for(j = 0; j < started_cmds_counted; j++){
				if(cmds_complete_cycles[j] > cmds_started_cycles[j]){
					unsigned long long delta = 1000 * 1000 * (cmds_complete_cycles[j] - cmds_started_cycles[j]);
					total_time += delta;
					cmds_accumulated++;
				}
			}
			do_div(total_time, tsc_khz);   // translate from cpu cycles to clock time (ns)
			// printk("host.c count thread: cmds counts %d and total time %lld\n", cmds_accumulated, total_time);
			
			perf_data->cmds_per_round[rounds] = cmds_accumulated;
			if (cmds_accumulated > 0){
				do_div(total_time, cmds_accumulated);
				perf_data->cmds_avg_lat_per_round[rounds] = total_time;
			}
			else
				perf_data->cmds_avg_lat_per_round[rounds] = 0;
			
			// printk("host.c count thread: cmds counts %d and avg time %lld\n", cmds_accumulated, perf_data->cmds_avg_lat_per_round[rounds]);

			mutex_lock(&perf_data->lock);
			perf_data->rounds++;	
			if(perf_data->rounds > 99){
				perf_data->rounds = 0;
			}
				
			perf_data->cmds_started[last_phase] = 0;
			perf_data->cmds_complete[last_phase] = 0;
			mutex_unlock(&perf_data->lock);
		}
	}
}

static int __init nvme_mdev_init(void)
{
	int ret;
    /* IO schd */
	schd_init();

	nvme_mdev_instance_types_init(&mdev_fops);
	ret = nvme_core_register_mdev_driver(&nvme_mdev_driver);
	if (ret) { 
		nvme_mdev_instance_types_fini(&mdev_fops);
		return ret;
	}

	pr_info("nvme_mdev with schd" NVME_MDEV_FIRMWARE_VERSION " loaded\n");

	/* IO schd */
	if (!tsk) {
		tsk = kthread_run(schd_thread, NULL, "mdev_scheduler_%d", 1);
		if (IS_ERR(tsk)) {
			pr_info("IO schd: start schd kthread failed.\n");
		}
		else {
			// kthread_bind(tsk, 1);
			// wake_up_process(tsk);
			pr_info("IO schd: start schd kthread successfully.\n");
		}
	}
	if(!data_tsk) {
		data_tsk = kthread_run(data_thread, NULL, "mdev_data_counter_%d", 1);
		if (IS_ERR(data_tsk)) {
			pr_info("IO schd: start data count kthread failed.\n");
		}
		else {
			// kthread_bind(data_tsk, 2);
			pr_info("IO schd: start data count kthread successfully.\n");
		}
	}

	return 0;
}

static void __exit nvme_mdev_exit(void)
{
    /* IO schd */
	hwq_fini();
	schd_remove();
	
	nvme_core_unregister_mdev_driver(&nvme_mdev_driver);
	nvme_mdev_hctrl_destroy_all();
	nvme_mdev_instance_types_fini(&mdev_fops);
	pr_info("nvme_mdev unloaded\n");
}

MODULE_IMPORT_NS(NVME_TARGET_PASSTHRU);
MODULE_AUTHOR("Maxim Levitsky <mlevitsk@redhat.com>");
MODULE_AUTHOR("Bo Peng <pengbo_michael@sjtu.edu.cn");
MODULE_LICENSE("GPL");
MODULE_VERSION(NVME_MDEV_FIRMWARE_VERSION);

module_init(nvme_mdev_init)
module_exit(nvme_mdev_exit)