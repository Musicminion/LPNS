/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Driver private data structures and helper macros
 * Copyright (c) 2019 - Maxim Levitsky
 */

#ifndef _MDEV_NVME_PRIV_H
#define _MDEV_NVME_PRIV_H

#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/vfio.h>
#include <linux/mdev.h>
#include <linux/pci.h>
#include <linux/eventfd.h>
#include <linux/byteorder/generic.h>
#include "../host/nvme.h"
#include "mdev.h"

#define NVME_MDEV_NVME_VER  NVME_VS(0x01, 0x03, 0x00)
#define NVME_MDEV_FIRMWARE_VERSION "1.0"

#define NVME_MDEV_PCI_VENDOR_ID		PCI_VENDOR_ID_REDHAT_QUMRANET
#define NVME_MDEV_PCI_DEVICE_ID		0x1234
#define NVME_MDEV_PCI_SUBVENDOR_ID	PCI_SUBVENDOR_ID_REDHAT_QUMRANET
#define NVME_MDEV_PCI_SUBDEVICE_ID	0
#define NVME_MDEV_PCI_REVISION		0x0

#define DB_STRIDE_SHIFT 4 /*4 = 1 cacheline */
#define MAX_VIRTUAL_QUEUES 30
#define MAX_VIRTUAL_QUEUE_DEPTH 0xFFFF
#define MAX_VIRTUAL_NAMESPACES 16 /* NSID = 1..16*/
#define MAX_VIRTUAL_IRQS 16

#define MAX_HOST_QUEUES 24
#define MAX_AER_COMMANDS 16
#define MAX_LOG_PAGES 16

/* IO schd */
#define MAX_VDEV 16
#define MAX_VIRTUAL_CONTROLLER 64
#define MAX_ALL_VIRTUAL_QUEUES (MAX_VIRTUAL_CONTROLLER * MAX_VIRTUAL_QUEUES)

#define QOS_TPT 0
#define QOS_LAT 1
#define QOS_DDL 2

#define VCTRL_MAX_IRQS 0x80

typedef unsigned long long cycles_t;

extern bool use_shadow_doorbell;
extern unsigned int io_timeout_ms;
extern unsigned int poll_timeout_ms;
extern unsigned int admin_poll_rate_ms;

static const char* QOS_name_table[3] = {
    "Throuput orientation",
    "Latency awared",
    "Deadline awared"
};

/* virtual submission queue*/
struct  nvme_vsq {
	u16 qid;
	u16 size;
	u16 head;	/*next item to read */

	struct nvme_command *data; /*the queue*/
	struct nvme_vcq *vcq; /* completion queue*/

	dma_addr_t iova;
	bool cont;

	u16 hsq;

	/* IO schd */
	unsigned int vctrl_id;
	bool assigned;
	u16 tail;
	bool wait;

	struct mutex lock;
};

/* virtual completion queue*/
struct nvme_vcq {
	/* basic queue settings */
	u16 qid;
	u16 size;
	u16 head;
	u16 tail;
	bool phase; /* current queue phase */

	volatile struct nvme_completion *data;

	/* number of items pending*/
	u16 pending;

	/* IRQ settings */
	int irq /* -1 if disabled*/;

	dma_addr_t iova;
	bool cont;

    /* IO schd */
    unsigned int vctrl_id;
    struct nvme_vsq *vsq;
    u32 real_phase;
    u32 last_phase;
    unsigned last_head;
    unsigned workload;
    unsigned hold_workload;
    unsigned weight;

    bool unassigned;
    struct mutex lock;
};

/*A virtual namespace */
struct nvme_mdev_vns {
	/* host nvme namespace that we are attached to it*/
	struct nvme_ns *host_ns;

	/* block device that corresponds to the partition of that namespace */
	struct block_device *host_part;
	fmode_t fmode;

	u32 nsid;

	/* NSID on the host*/
	u32 host_nsid;

	/* host partition ID*/
	unsigned int host_partid;

	/* Offset inside the host namespace (start of the partition)*/
	u64 host_lba_offset;

	/* size of each block on the real namespace, same for host and guest */
	u8 blksize_shift;

	/* size of the namespace in lbas*/
	u64 ns_size;

	/* is the namespace read only?*/
	bool readonly;

	/* UUID of this namespace */
	uuid_t uuid;

	/* Optimal IO boundary*/
	u16 noiob;
};

/* Virtual IOMMU */
struct nvme_mdev_viommu {
	struct device *hw_dev;
	struct device *sw_dev;

	/* dma/prp bookkeeping */
	struct rb_root_cached maps_tree;
	struct list_head maps_list;
	struct nvme_mdev_vctrl *vctrl;
};

struct doorbell {
	volatile __le32 sqt;
	u8 rsvd1[(4 << DB_STRIDE_SHIFT) - sizeof(__le32)];
	volatile __le32 cqh;
	u8 rsvd2[(4 << DB_STRIDE_SHIFT) - sizeof(__le32)];
};

/* MMIO state */
struct nvme_mdev_user_ctrl_mmio {
	u32 cc;		/* controller configuration */
	u32 csts;	/* controller status */
	u64 cap		/* controller capabilities*/;

	/* admin queue location & size */
	u32 aqa;
	u32 asql;
	u32 asqh;
	u32 acql;
	u32 acqh;

	bool shadow_db_supported;
	bool shadow_db_en;

	/* Regular doorbells */
	struct page *dbs_page;
	struct page *fake_eidx_page;
	void *db_page_kmap;
	void *fake_eidx_kmap;

	/* Shadow doorbells */
	struct page_map sdb_map;
	struct page_map seidx_map;

	/* Current doorbell mappings */
	volatile struct doorbell *dbs;
	volatile struct doorbell *eidxs;
};

/* pci configuration space of the device*/
#define PCI_CFG_SIZE 4096
struct nvme_mdev_pci_cfg_space {
	u8 *values;
	u8 *wmask;

	u8 pmcap;
	u8 pciecap;
	u8 msixcap;
	u8 end;
};

/*IRQ state of the controller */
struct nvme_mdev_user_irq {
	struct eventfd_ctx *trigger;
	/* IRQ coalescing */
	bool irq_coalesc_en;
	ktime_t irq_time;
	unsigned int irq_pending_cnt;
};

enum nvme_mdev_irq_mode {
	NVME_MDEV_IMODE_NONE,
	NVME_MDEV_IMODE_INTX,
	NVME_MDEV_IMODE_MSIX,
};

struct nvme_mdev_user_irqs {
	/* one of VFIO_PCI_{INTX|MSI|MSIX}_IRQ_INDEX */
	enum nvme_mdev_irq_mode mode;

	struct nvme_mdev_user_irq vecs[MAX_VIRTUAL_IRQS];
	/* user interrupt coalescing settings */
	u8 irq_coalesc_max;
	unsigned int irq_coalesc_time_us;
	/* device removal trigger*/
	struct eventfd_ctx *request_trigger;
};

/*AER state */
struct nvme_mdev_user_events {
	/* async event request CIDs*/
	u16 aer_cids[MAX_AER_COMMANDS];
	unsigned int aer_cid_count;

	/* events that are enabled */
	unsigned long events_enabled[BITS_TO_LONGS(MAX_LOG_PAGES)];

	/* events that are masked till next log page read*/
	unsigned long events_masked[BITS_TO_LONGS(MAX_LOG_PAGES)];

	/* events that are pending to be sent when user gives us an AER*/
	unsigned long  events_pending[BITS_TO_LONGS(MAX_LOG_PAGES)];
	u32 event_values[MAX_LOG_PAGES];
};

/* host IO queue */
struct nvme_mdev_hq {
	unsigned int usecount;
	struct list_head link;
	unsigned int hqid;

	/* IO schd */
	unsigned int vctrl_id;
	bool bound;
};

/* IO region abstraction (BARs, the PCI config space */
struct nvme_mdev_vctrl;
typedef int (*region_access_fn) (struct nvme_mdev_vctrl *vctrl,
				 u16 offset, char *buf,
				 u32 size, bool is_write);

struct nvme_mdev_io_region {
	unsigned int size;
	region_access_fn rw;

	/* IF != NULL, the mmap_area_start/size specify the mmaped window
	 * of this region
	 */
	const struct vm_operations_struct *mmap_ops;
	unsigned int mmap_area_start;
	unsigned int mmap_area_size;
};

struct nvme_mdev_perf
{
	/* number of IO commands received */
	unsigned long long cmds_started;
	unsigned long long cmds_complete;
	unsigned long long interrupts_sent;

	unsigned long long cycles_send_to_hw;
	unsigned long long cycles_receive_from_hw;
	unsigned long long cycles_irq_delivery;
};

struct nvme_mdev_perf_data 
{
	/* calculate perf data per 2ms */
	struct mutex lock;
	int cmds_per_round[100];
	unsigned long long cmds_avg_lat_per_round[100];   // ns
	unsigned long long cmds_tail_lat_per_round[100];    // ns
	int rounds;
	int phase;

	unsigned long long cmds_started[2];
	unsigned long long cmds_complete[2];
	u16 cmds_started_id[2][1000];
	u16 cmds_complete_id[2][1000];
	unsigned long long cmds_started_cycles[2][1000];
	unsigned long long cmds_complete_cycles[2][1000];
};

/*Virtual NVME controller state */
struct nvme_mdev_vctrl {
	struct kref ref;
	struct mutex lock;
	struct list_head link;

	struct mdev_device *mdev;
	struct nvme_mdev_hctrl *hctrl;
	bool inuse;

	struct nvme_mdev_io_region regions[VFIO_PCI_NUM_REGIONS];

	/* virtual controller state */
	struct nvme_mdev_user_ctrl_mmio mmio;
	struct nvme_mdev_pci_cfg_space pcicfg;
	struct nvme_mdev_user_irqs irqs;
	struct nvme_mdev_user_events events;

	/* emulated namespaces */
	struct nvme_mdev_vns *namespaces[MAX_VIRTUAL_NAMESPACES];
	__le32 ns_log[MAX_VIRTUAL_NAMESPACES];
	unsigned int ns_log_size;

	/* emulated submission queues*/
	struct nvme_vsq vsqs[MAX_VIRTUAL_QUEUES];
	unsigned long vsq_en[BITS_TO_LONGS(MAX_VIRTUAL_QUEUES)];

	/* emulated completion queues*/
	unsigned long vcq_en[BITS_TO_LONGS(MAX_VIRTUAL_QUEUES)];
	struct nvme_vcq vcqs[MAX_VIRTUAL_QUEUES];

	/* Host IO queues*/
	int max_host_hw_queues;
	struct list_head host_hw_queues;
	
	struct mutex host_hw_queues_lock;

	/* Interface to access user memory */
	struct notifier_block vfio_map_notifier;
	struct notifier_block vfio_unmap_notifier;
	struct nvme_mdev_viommu viommu;

	/* the IO thread */
	struct task_struct *iothread;
	bool iothread_parked;
	bool io_idle;
	ktime_t now;

	/* Settings */
	unsigned int arb_burst_shift;
	u8 worload_hint;
	unsigned int iothread_cpu;

	/* Identification*/
	char subnqn[256];
	char serial[9];

	bool vctrl_paused; /* true when the host device paused our IO */

	struct nvme_mdev_perf perf;
	struct nvme_mdev_perf last_perf;
	struct nvme_mdev_perf_data *perf_data;
    
    /* IO schd */
	unsigned int id;
	bool wait;
	unsigned int type;
	unsigned int qos_val;
};

/* mdev instance type*/
struct nvme_mdev_inst_type {
	unsigned int max_hw_queues;
	char name[16];
	struct attribute_group *attrgroup;
};

/*Abstraction of the host controller that we are connected to */
struct nvme_mdev_hctrl {
	struct mutex lock;

	/* numa node of the host controller*/
	int node;

	struct list_head link;
	struct kref ref;
	bool removing;

	/* for reference counting */
	struct nvme_ctrl *nvme_ctrl;

	/* Host area*/
	u16 oncs;
	u8 mdts;
	unsigned int id;

	/* book-keeping for number of host queues we can allocate*/
	unsigned int nr_host_queues;
	struct list_head host_hw_queues;

	/* IO schd */
	unsigned int total_host_queues;
};

/* IO schd */
struct nvme_mdev_client {
	struct nvme_mdev_vctrl *vctrl;
	bool in_use;
	u16 *host_qids;
	u16 v_workloads;  // virtual workloads
	u16 t_workloads;  // total workloads
	u16 workloads;
	unsigned long long cmds_avg_lat;
	unsigned long long cmds_tail_lat;
};

struct nvme_mdev_scheduler {
	struct nvme_mdev_client **clients;
	struct nvme_mdev_client *qos_ddl_client;
	int max_clients;
	int curr_client;

	struct mutex lock;
	bool in_schd;

	wait_queue_head_t waitq;

	struct nvme_vcq *cqp[MAX_ALL_VIRTUAL_QUEUES];
	unsigned cq_num;
	bool need_schd;
	unsigned int start_index; // start index of next schd cycle (range: 0 ~ cq_num - 1)

	u16 nr_used_hwqs;
	u16 total_hwqs;
	struct nvme_mdev_hq *host_hw_queues[MAX_HOST_QUEUES];

	unsigned int mdev_device_num;
	unsigned int active_mdev_dev_num; // Numbers of the no-latency-sensitive VMs with avtive workloads
	int threshold;
	int total_threshold;
	volatile bool thread_parked;
};

// mdev type
struct mdev_parent {
	struct device *dev;
	const struct mdev_parent_ops *ops;
	struct kref ref;
	struct list_head next;
	struct kset *mdev_types_kset;
	struct list_head type_list;
	/* Synchronize device creation/removal with parent unregistration */
	struct rw_semaphore unreg_sem;
};

struct mdev_type {
	struct kobject kobj;
	struct kobject *devices_kobj;
	struct mdev_parent *parent;
	struct list_head next;
	unsigned int type_group_id;
};


/* vctrl.c*/
struct nvme_mdev_vctrl *nvme_mdev_vctrl_create(struct mdev_device *mdev,
					       struct nvme_mdev_hctrl *hctrl,
					       unsigned int max_host_queues);

int nvme_mdev_vctrl_destroy(struct nvme_mdev_vctrl *vctrl);

int nvme_mdev_vctrl_open(struct nvme_mdev_vctrl *vctrl);
void nvme_mdev_vctrl_release(struct nvme_mdev_vctrl *vctrl);

void nvme_mdev_vctrl_pause(struct nvme_mdev_vctrl *vctrl);
void nvme_mdev_vctrl_resume(struct nvme_mdev_vctrl *vctrl);

bool nvme_mdev_vctrl_enable(struct nvme_mdev_vctrl *vctrl,
			    dma_addr_t cqiova, dma_addr_t sqiova, u32 sizes);

void nvme_mdev_vctrl_disable(struct nvme_mdev_vctrl *vctrl);

void nvme_mdev_vctrl_reset(struct nvme_mdev_vctrl *vctrl);
void __nvme_mdev_vctrl_reset(struct nvme_mdev_vctrl *vctrl, bool pci_reset);

void nvme_mdev_vctrl_add_region(struct nvme_mdev_vctrl *vctrl,
				unsigned int index, unsigned int size,
				region_access_fn access_fn);

void nvme_mdev_vctrl_region_set_mmap(struct nvme_mdev_vctrl *vctrl,
				     unsigned int index,
				     unsigned int offset,
				     unsigned int size,
				     const struct vm_operations_struct *ops);

void nvme_mdev_vctrl_region_disable_mmap(struct nvme_mdev_vctrl *vctrl,
					 unsigned int index);

void nvme_mdev_vctrl_bind_iothread(struct nvme_mdev_vctrl *vctrl,
				   unsigned int cpu);

int nvme_mdev_vctrl_set_shadow_doorbell_supported(struct nvme_mdev_vctrl *vctrl,
						  bool enable);

int nvme_mdev_vctrl_hq_alloc(struct nvme_mdev_vctrl *vctrl);
void nvme_mdev_vctrl_hq_free(struct nvme_mdev_vctrl *vctrl, u16 qid);
unsigned int nvme_mdev_vctrl_hqs_list(struct nvme_mdev_vctrl *vctrl, u16 *out);
bool nvme_mdev_vctrl_is_dead(struct nvme_mdev_vctrl *vctrl);

int nvme_mdev_vctrl_viommu_map(struct nvme_mdev_vctrl *vctrl, u32 flags,
			       dma_addr_t iova, u64 size);

int nvme_mdev_vctrl_viommu_unmap(struct nvme_mdev_vctrl *vctrl,
				 dma_addr_t iova, u64 size);

void nvme_mdev_vctrl_print_hwq(struct nvme_mdev_vctrl *vctrl);

/* hctrl.c*/
struct nvme_mdev_inst_type *nvme_mdev_inst_type_get(const char *name);
struct nvme_mdev_hctrl *nvme_mdev_hctrl_lookup_get(struct device *parent);
void nvme_mdev_hctrl_put(struct nvme_mdev_hctrl *hctrl);

int nvme_mdev_hctrl_hqs_available(struct nvme_mdev_hctrl *hctrl);

bool nvme_mdev_hctrl_hqs_reserve(struct nvme_mdev_hctrl *hctrl,
				 unsigned int n);
void nvme_mdev_hctrl_hqs_unreserve(struct nvme_mdev_hctrl *hctrl,
				   unsigned int n);

int nvme_mdev_hctrl_hq_alloc(struct nvme_mdev_hctrl *hctrl);
void nvme_mdev_hctrl_hq_free(struct nvme_mdev_hctrl *hctrl, u16 qid);
bool nvme_mdev_hctrl_hq_can_submit(struct nvme_mdev_hctrl *hctrl, u16 qid);
bool nvme_mdev_hctrl_hq_check_op(struct nvme_mdev_hctrl *hctrl, u8 optcode);

int nvme_mdev_hctrl_hq_submit(struct nvme_mdev_hctrl *hctrl,
			      u16 qid, u64 tag,
			      struct nvme_command *cmd,
			      struct nvme_ext_data_iter *datait);

int nvme_mdev_hctrl_hq_poll(struct nvme_mdev_hctrl *hctrl,
			    u32 qid,
			    struct nvme_ext_cmd_result *results,
			    unsigned int max_len);

void nvme_mdev_hctrl_destroy_all(void);

void nvme_mdev_vctrl_hq_unbind(struct nvme_mdev_vctrl *vctrl);

void nvme_mdev_vctrl_hq_bind(struct nvme_mdev_vctrl *vctrl);

/* io.c */
int nvme_mdev_io_create(struct nvme_mdev_vctrl *vctrl, unsigned int cpu);
void nvme_mdev_io_free(struct nvme_mdev_vctrl *vctrl);
void nvme_mdev_io_pause(struct nvme_mdev_vctrl *vctrl);
void nvme_mdev_io_resume(struct nvme_mdev_vctrl *vctrl);
void nvme_mdev_assert_io_not_running(struct nvme_mdev_vctrl *vctrl);

/* mmio.c*/
int nvme_mdev_mmio_create(struct nvme_mdev_vctrl *vctrl);
void nvme_mdev_mmio_open(struct nvme_mdev_vctrl *vctrl);
void nvme_mdev_mmio_reset(struct nvme_mdev_vctrl *vctrl, bool pci_reset);
void nvme_mdev_mmio_free(struct nvme_mdev_vctrl *vctrl);

int nvme_mdev_mmio_enable_dbs(struct nvme_mdev_vctrl *vctrl);
int nvme_mdev_mmio_enable_dbs_shadow(struct nvme_mdev_vctrl *vctrl,
				     dma_addr_t sdb_iova, dma_addr_t eidx_iova);

void nvme_mdev_mmio_viommu_update(struct nvme_mdev_vctrl *vctrl);
void nvme_mdev_mmio_disable_dbs(struct nvme_mdev_vctrl *vctrl);
bool nvme_mdev_mmio_db_check(struct nvme_mdev_vctrl *vctrl,
			     u16 qid, u16 size, u16 db);

/* pci.c*/
int nvme_mdev_pci_create(struct nvme_mdev_vctrl *vctrl);
void nvme_mdev_pci_free(struct nvme_mdev_vctrl *vctrl);
void nvme_mdev_pci_setup_bar(struct nvme_mdev_vctrl *vctrl,
			     u8 bar, unsigned int size,
			     region_access_fn access_fn);
/* adm.c*/
void nvme_mdev_adm_process_sq(struct nvme_mdev_vctrl *vctrl);

/* events.c */
void nvme_mdev_events_init(struct nvme_mdev_vctrl *vctrl);
void nvme_mdev_events_reset(struct nvme_mdev_vctrl *vctrl);

int nvme_mdev_event_request_receive(struct nvme_mdev_vctrl *vctrl, u16 cid);
void nvme_mdev_event_process_ack(struct nvme_mdev_vctrl *vctrl, u8 log_page);

void nvme_mdev_event_send(struct nvme_mdev_vctrl *vctrl,
			  enum nvme_async_event_type type,
			  enum nvme_async_event info);

u32 nvme_mdev_event_read_aen_config(struct nvme_mdev_vctrl *vctrl);
void nvme_mdev_event_set_aen_config(struct nvme_mdev_vctrl *vctrl, u32 value);

/* irq.c*/
void nvme_mdev_irqs_setup(struct nvme_mdev_vctrl *vctrl);
void nvme_mdev_irqs_reset(struct nvme_mdev_vctrl *vctrl);

int nvme_mdev_irqs_enable(struct nvme_mdev_vctrl *vctrl,
			  enum nvme_mdev_irq_mode mode);
void nvme_mdev_irqs_disable(struct nvme_mdev_vctrl *vctrl,
			    enum nvme_mdev_irq_mode mode);

int nvme_mdev_irqs_set_triggers(struct nvme_mdev_vctrl *vctrl,
				int start, int count, int32_t *fds);
int nvme_mdev_irqs_set_unplug_trigger(struct nvme_mdev_vctrl *vctrl,
				      int32_t fd);

void nvme_mdev_irq_raise_unplug_event(struct nvme_mdev_vctrl *vctrl,
				      unsigned int count);
void nvme_mdev_irq_raise(struct nvme_mdev_vctrl *vctrl,
			 unsigned int index);
void nvme_mdev_irq_trigger(struct nvme_mdev_vctrl *vctrl,
			   unsigned int index);
void nvme_mdev_irq_cond_trigger(struct nvme_mdev_vctrl *vctrl,
				unsigned int index);
void nvme_mdev_irq_clear(struct nvme_mdev_vctrl *vctrl,
			 unsigned int index);

/* ns.c*/
int nvme_mdev_vns_open(struct nvme_mdev_vctrl *vctrl,
		       u32 host_nsid, unsigned int host_partid);
int nvme_mdev_vns_destroy(struct nvme_mdev_vctrl *vctrl,
			  u32 user_nsid);
void nvme_mdev_vns_destroy_all(struct nvme_mdev_vctrl *vctrl);

struct nvme_mdev_vns *nvme_mdev_vns_from_vnsid(struct nvme_mdev_vctrl *vctrl,
					       u32 user_ns_id);

int nvme_mdev_vns_print_description(struct nvme_mdev_vctrl *vctrl,
				    char *buf, unsigned int size);
void nvme_mdev_vns_host_ns_update(struct nvme_mdev_vctrl *vctrl,
				  u32 host_nsid, bool removed);

void nvme_mdev_vns_log_reset(struct nvme_mdev_vctrl *vctrl);

/* vcq.c */
int nvme_mdev_vcq_init(struct nvme_mdev_vctrl *vctrl, u16 qid,
		       dma_addr_t iova, bool cont, u16 size, int irq);

int nvme_mdev_vcq_viommu_update(struct nvme_mdev_viommu *viommu,
				struct nvme_vcq *q);

void nvme_mdev_vcq_delete(struct nvme_mdev_vctrl *vctrl, u16 qid);
void nvme_mdev_vcq_process(struct nvme_mdev_vctrl *vctrl, u16 qid,
			   bool trigger_irqs);

bool nvme_mdev_vcq_flush(struct nvme_mdev_vctrl *vctrl, u16 qid);
bool nvme_mdev_vcq_reserve_space(struct nvme_vcq *q);

void nvme_mdev_vcq_write_io(struct nvme_mdev_vctrl *vctrl,
			    struct nvme_vcq *q, u16 sq_head,
			    u16 sqid, u16 cid, u16 status);

void nvme_mdev_vcq_write_adm(struct nvme_mdev_vctrl *vctrl,
			     struct nvme_vcq *q, u32 dw0,
			     u16 sq_head, u16 cid, u16 status);
/* vsq.c*/
int nvme_mdev_vsq_init(struct nvme_mdev_vctrl *vctrl, u16 qid,
		       dma_addr_t iova, bool cont, u16 size, u16 cqid);

int nvme_mdev_vsq_viommu_update(struct nvme_mdev_viommu *viommu,
				struct nvme_vsq *q);

void nvme_mdev_vsq_delete(struct nvme_mdev_vctrl *vctrl, u16 qid);

bool nvme_mdev_vsq_has_data(struct nvme_mdev_vctrl *vctrl,
			    struct nvme_vsq *q);

const struct nvme_command *nvme_mdev_vsq_get_cmd(struct nvme_mdev_vctrl *vctrl,
						 struct nvme_vsq *q);

void nvme_mdev_vsq_cmd_done_io(struct nvme_mdev_vctrl *vctrl,
			       u16 sqid, u16 cid, u16 status);
void nvme_mdev_vsq_cmd_done_adm(struct nvme_mdev_vctrl *vctrl,
				u32 dw0, u16 cid, u16 status);
bool nvme_mdev_vsq_suspend_io(struct nvme_mdev_vctrl *vctrl, u16 sqid);

/* udata.c*/
void nvme_mdev_udata_iter_setup(struct nvme_mdev_viommu *viommu,
				struct nvme_ext_data_iter *iter);

int nvme_mdev_udata_iter_set_dptr(struct nvme_ext_data_iter *it,
				  const union nvme_data_ptr *dptr, u64 size);

struct nvme_ext_data_iter *
nvme_mdev_kdata_iter_alloc(struct nvme_mdev_viommu *viommu, unsigned int size);

int nvme_mdev_read_from_udata(void *dst, struct nvme_ext_data_iter *srcit,
			      u64 size);

int nvme_mdev_write_to_udata(struct nvme_ext_data_iter *dstit, void *src,
			     u64 size);

void *nvme_mdev_udata_queue_vmap(struct nvme_mdev_viommu *viommu,
				 dma_addr_t iova,
				 unsigned int size, bool cont);
/* viommu.c */
void nvme_mdev_viommu_init(struct nvme_mdev_viommu *viommu,
			   struct device *sw_dev,
			   struct device *hw_dev);

int nvme_mdev_viommu_add(struct nvme_mdev_viommu *viommu, u32 flags,
			 dma_addr_t iova, u64 size);

int nvme_mdev_viommu_remove(struct nvme_mdev_viommu *viommu,
			    dma_addr_t iova, u64 size);

int nvme_mdev_viommu_translate(struct nvme_mdev_viommu *viommu,
			       dma_addr_t iova,
			       dma_addr_t *physical,
			       dma_addr_t *host_iova);

int nvme_mdev_viommu_create_kmap(struct nvme_mdev_viommu *viommu,
				 dma_addr_t iova, struct page_map *page);

void nvme_mdev_viommu_free_kmap(struct nvme_mdev_viommu *viommu,
				struct page_map *page);

void nvme_mdev_viommu_update_kmap(struct nvme_mdev_viommu *viommu,
				  struct page_map *page);

void nvme_mdev_viommu_reset(struct nvme_mdev_viommu *viommu);


/* IO schd */
/* host.c */
void hwq_init(struct nvme_ctrl *ctrl);

int nvme_mdev_vctrl_reserved_workload(struct nvme_vsq *vsq);

int nvme_mdev_vctrl_hold_workload(struct nvme_vsq *vsq);

int schd_add_vctrl(struct nvme_mdev_vctrl *vctrl);

int schd_remove_vctrl(struct nvme_mdev_vctrl *vctrl);

void schd_remove_cq(struct nvme_mdev_vctrl *vctrl, u16 qid);

void schd_remove_hwq(u16 qid);

int schd_get_hwq(u16 qid);

/* some utilities*/

#define store_le64(address, value) (*((__le64 *)(address)) = cpu_to_le64(value))
#define store_le32(address, value) (*((__le32 *)(address)) = cpu_to_le32(value))
#define store_le16(address, value) (*((__le16 *)(address)) = cpu_to_le16(value))
#define store_le8(address, value)  (*((u8 *)(address)) = (value))

#define load_le16(address) le16_to_cpu(*(__le16 *)(address))
#define load_le32(address) le32_to_cpu(*(__le32 *)(address))

#define store_strsp(dst, src) \
	memcpy_and_pad(dst, sizeof(dst), src, sizeof(src) - 1, ' ')

#define DNR(e) ((e) | NVME_SC_DNR)

#define PAGE_ADDRESS(address) ((address) & PAGE_MASK)
#define OFFSET_IN_PAGE(address) ((address) & ~(PAGE_MASK))

#define _DBG(vctrl, fmt, ...) \
	dev_dbg(mdev_dev((vctrl)->mdev), fmt, ##__VA_ARGS__)

#define _INFO(vctrl, fmt, ...) \
	dev_info(mdev_dev((vctrl)->mdev), fmt, ##__VA_ARGS__)

#define _WARN(vctrl, fmt, ...) \
	dev_warn(mdev_dev((vctrl)->mdev), fmt, ##__VA_ARGS__)

#define mdev_to_vctrl(mdev) \
	((struct nvme_mdev_vctrl *)mdev_get_drvdata(mdev))

#define dev_to_vctrl(mdev) \
	mdev_to_vctrl(mdev_from_dev(dev))

#define RSRV_NSID (BIT(1))
#define RSRV_DW23 (BIT(2) | BIT(3))
#define RSRV_MPTR (BIT(4) | BIT(5))

#define RSRV_DPTR (BIT(6) | BIT(7) | BIT(8) | BIT(9))
#define RSRV_DPTR_PRP2 (BIT(8) | BIT(9))

#define RSRV_DW10_15 (BIT(10) | BIT(11) | BIT(12) | BIT(13) | BIT(14) | BIT(15))
#define RSRV_DW11_15 (BIT(11) | BIT(12) | BIT(13) | BIT(14) | BIT(15))
#define RSRV_DW12_15 (BIT(12) | BIT(13) | BIT(14) | BIT(15))
#define RSRV_DW13_15 (BIT(13) | BIT(14) | BIT(15))
#define RSRV_DW14_15 (BIT(14) | BIT(15))

static inline bool check_reserved_dwords(const u32 *dwords,
					 int count, unsigned long bitmask)
{
	int bit;

	if (WARN_ON(count > BITS_PER_TYPE(long)))
		return false;

	for_each_set_bit(bit, &bitmask, count)
		if (dwords[bit])
			return false;
	return true;
}

static inline bool check_range(u64 start, u64 size, u64 end)
{
	u64 test = start + size;

	/* check for overflow */
	if (test < start || test < size)
		return false;
	return test <= end;
}

/* Rough translation of internal errors to the NVME errors */
static inline int nvme_mdev_translate_error(int error)
{
	// nvme status, including no error (NVME_SC_SUCCESS)
	if (error >= 0)
		return error;

	switch (error) {
	case -ENOMEM:
		/*no memory - truly an internal error*/
		return NVME_SC_INTERNAL;
	case -ENOSPC:
		/* Happens when user sends to large PRP list
		 * User shoudn't do this since the maximum transfer size
		 * is specified in the controller caps
		 */
		return DNR(NVME_SC_DATA_XFER_ERROR);
	case -EFAULT:
		/* Bad memory pointers in the prp lists*/
		return DNR(NVME_SC_DATA_XFER_ERROR);
	case -EINVAL:
		/* Bad prp offsets in the prp lists/command*/
		return DNR(NVME_SC_PRP_INVALID_OFFSET);
	default:
		/*Shouldn't happen */
		WARN_ON_ONCE(true);
		return NVME_SC_INTERNAL;
	}
}

static inline bool timeout(ktime_t event, ktime_t now, unsigned long timeout_ms)
{
	return ktime_ms_delta(now, event) > (long)timeout_ms;
}

static inline const char* get_qos_type(unsigned long int type)
{
    pr_info("get_qos_type: %lu\n", type);
    return QOS_name_table[type];
}

extern struct mdev_parent_ops mdev_fops;
extern struct list_head nvme_mdev_vctrl_list;
extern struct mutex nvme_mdev_vctrl_list_mutex;

/* IO schd*/
extern struct nvme_mdev_scheduler *schd;
extern struct task_struct *tsk;

#endif // _MDEV_NVME_H
