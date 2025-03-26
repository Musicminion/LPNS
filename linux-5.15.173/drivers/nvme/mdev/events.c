// SPDX-License-Identifier: GPL-2.0+
/*
 * NVMe async events implementation (AER, changed namespace log)
 * Copyright (c) 2019 - Maxim Levitsky
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include "priv.h"

/* complete an AER event on the admin queue if it is pending*/
static void nvme_mdev_event_complete(struct nvme_mdev_vctrl *vctrl)
{
	u16 lid, cid;
	u32 dw0;

	for_each_set_bit(lid, vctrl->events.events_pending, MAX_LOG_PAGES) {
		/* we have pending aer requests, but no requests*/
		if (vctrl->events.aer_cid_count == 0)
			break;

		if (!test_bit(lid, vctrl->events.events_enabled))
			continue;

		cid = vctrl->events.aer_cids[--vctrl->events.aer_cid_count];
		dw0 = vctrl->events.event_values[lid];
		clear_bit(lid, vctrl->events.events_pending);

		_DBG(vctrl,
		     "AEN: replying to AER (CID=%d) with status 0x%08x\n",
		     cid, dw0);

		nvme_mdev_vsq_cmd_done_adm(vctrl, dw0, cid, NVME_SC_SUCCESS);
	}
}

/* deal with received async event request from the user*/
int nvme_mdev_event_request_receive(struct nvme_mdev_vctrl *vctrl,
				    u16 cid)
{
	int cnt = vctrl->events.aer_cid_count;

	if (cnt >= MAX_AER_COMMANDS)
		return DNR(NVME_SC_ASYNC_LIMIT);

	/* don't allow AER to be pending if there is no space left in the
	 * completion queue permanently
	 */
	if ((cnt + 1) >= vctrl->vcqs[0].size - 1)
		return DNR(NVME_SC_ASYNC_LIMIT);

	vctrl->events.aer_cids[cnt++] = cid;
	vctrl->events.aer_cid_count = cnt;

	_DBG(vctrl, "AEN: received new request (cid=%d)\n", cid);
	nvme_mdev_event_complete(vctrl);
	return -1;
}

/* Send an async event request */
void nvme_mdev_event_send(struct nvme_mdev_vctrl *vctrl,
			  enum nvme_async_event_type type,
			  enum nvme_async_event info)
{
	u8 log_page;
	u32 event;

	// determine the log page for event types that we support
	switch (type) {
	case NVME_AER_TYPE_ERROR:
		log_page = NVME_LOG_ERROR;
		break;
	case NVME_AER_TYPE_SMART:
		log_page = NVME_LOG_SMART;
		break;
	case NVME_AER_TYPE_NOTICE:
		WARN_ON(info != NVME_AER_NOTICE_NS_CHANGED);
		log_page = NVME_LOG_CHANGED_NS;
		break;
	default:
		WARN_ON(1);
		return;
	}

	if (test_and_set_bit(log_page, vctrl->events.events_masked))
		return;

	event = (u32)type | ((u32)info << 8) | ((u32)log_page << 16);
	vctrl->events.event_values[log_page] = event;
	set_bit(log_page, vctrl->events.events_masked);
	set_bit(log_page, vctrl->events.events_pending);
	nvme_mdev_event_complete(vctrl);
}

u32 nvme_mdev_event_read_aen_config(struct nvme_mdev_vctrl *vctrl)
{
	u32 value = 0;

	if (test_bit(NVME_LOG_CHANGED_NS, vctrl->events.events_enabled))
		value |= NVME_AEN_CFG_NS_ATTR;
	return value;
}

void nvme_mdev_event_set_aen_config(struct nvme_mdev_vctrl *vctrl, u32 value)
{
	_DBG(vctrl, "AEN: set config: 0x%04x\n", value);

	if (value & NVME_AEN_CFG_NS_ATTR)
		set_bit(NVME_LOG_CHANGED_NS, vctrl->events.events_enabled);
	else
		clear_bit(NVME_LOG_CHANGED_NS, vctrl->events.events_enabled);

	nvme_mdev_event_complete(vctrl);
}

/* called when user acks an log page which causes an AER event to be unmasked*/
void nvme_mdev_event_process_ack(struct nvme_mdev_vctrl *vctrl, u8 log_page)
{
	lockdep_assert_held(&vctrl->lock);

	_DBG(vctrl, "AEN: log page %d ACK\n", log_page);

	if (log_page >= MAX_LOG_PAGES)
		return;

	clear_bit(log_page, vctrl->events.events_masked);
	nvme_mdev_event_complete(vctrl);
}

/* reset event state*/
void nvme_mdev_events_init(struct nvme_mdev_vctrl *vctrl)
{
	memset(&vctrl->events, 0, sizeof(vctrl->events));
	set_bit(NVME_LOG_CHANGED_NS, vctrl->events.events_enabled);
	set_bit(NVME_LOG_ERROR, vctrl->events.events_enabled);
}

/* reset event state*/
void nvme_mdev_events_reset(struct nvme_mdev_vctrl *vctrl)
{
	memset(&vctrl->events, 0, sizeof(vctrl->events));
}

