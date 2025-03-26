// SPDX-License-Identifier: GPL-2.0+
/*
 * Virtual IOMMU - mapping user memory to the real device
 * Copyright (c) 2019 - Maxim Levitsky
 */
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/mdev.h>
#include <linux/vmalloc.h>
#include <linux/nvme.h>
#include <linux/iommu.h>
#include <linux/interval_tree_generic.h>
#include "priv.h"

struct mem_mapping {
	struct rb_node rb;
	struct list_head link;

	dma_addr_t __subtree_last;
	dma_addr_t iova_start; /* first iova in this mapping*/
	dma_addr_t iova_last;  /* last iova in this mapping*/

	unsigned long pfn;  /* physical address of this mapping */
	dma_addr_t host_iova;  /* dma mapping to the real device*/
};

#define map_len(m) (((m)->iova_last - (m)->iova_start) + 1ULL)
#define map_pages(m) (map_len(m) >> PAGE_SHIFT)
#define START(node) ((node)->iova_start)
#define LAST(node) ((node)->iova_last)

INTERVAL_TREE_DEFINE(struct mem_mapping, rb, dma_addr_t, __subtree_last,
		     START, LAST, static inline, viommu_int_tree);

static void nvme_mdev_viommu_dbg_dma_range(struct nvme_mdev_viommu *viommu,
					   struct mem_mapping *map,
					   const char *action)
{
	dma_addr_t iova_start  = map->iova_start;
	dma_addr_t iova_end    = map->iova_start + map_len(map) - 1;
	dma_addr_t hiova_start = map->host_iova;
	dma_addr_t hiova_end   = map->host_iova  + map_len(map) - 1;

	_DBG(viommu->vctrl,
	     "vIOMMU: %s RW IOVA %pad-%pad -> DMA %pad-%pad\n",
	     action, &iova_start, &iova_end, &hiova_start, &hiova_end);
}

/* unpin N pages starting at given IOVA*/
static void nvme_mdev_viommu_unpin_pages(struct nvme_mdev_viommu *viommu,
					 dma_addr_t iova, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		unsigned long  user_pfn = (iova >> PAGE_SHIFT) + i;
		int ret = vfio_unpin_pages(viommu->sw_dev, &user_pfn, 1);

		WARN_ON(ret != 1);
	}
}

/* User memory init code*/
void nvme_mdev_viommu_init(struct nvme_mdev_viommu *viommu,
			   struct device *sw_dev,
			   struct device *hw_dev)
{
	viommu->sw_dev = sw_dev;
	viommu->hw_dev = hw_dev;
	viommu->maps_tree = RB_ROOT_CACHED;
	INIT_LIST_HEAD(&viommu->maps_list);
}

/* User memory end code*/
void nvme_mdev_viommu_reset(struct nvme_mdev_viommu *viommu)
{
	nvme_mdev_viommu_remove(viommu, 0, 0xFFFFFFFFFFFFFFFFULL);
	WARN_ON(!list_empty(&viommu->maps_list));
}

/* Adds a new range of user memory*/
int nvme_mdev_viommu_add(struct nvme_mdev_viommu *viommu,
			 u32 flags,
			 dma_addr_t iova,
			 u64 size)
{
	u64 offset;
	dma_addr_t iova_end = iova + size - 1;
	struct mem_mapping *map = NULL, *tmp;
	LIST_HEAD(new_mappings_list);
	int ret;

	if (!(flags & VFIO_DMA_MAP_FLAG_READ) ||
	    !(flags & VFIO_DMA_MAP_FLAG_WRITE)) {
		const char *type = "none";

		if (flags & VFIO_DMA_MAP_FLAG_READ)
			type = "RO";
		else if (flags & VFIO_DMA_MAP_FLAG_WRITE)
			type = "WO";

		_DBG(viommu->vctrl, "vIOMMU: IGN %s IOVA %pad-%pad\n",
		     type, &iova, &iova_end);
		return 0;
	}

	WARN_ON_ONCE(nvme_mdev_viommu_remove(viommu, iova, size) != 0);

	if (WARN_ON_ONCE(size & ~PAGE_MASK))
		return -EINVAL;

	// VFIO pinning all the pages
	for (offset = 0; offset < size; offset += PAGE_SIZE) {
		unsigned long vapfn = ((iova + offset) >> PAGE_SHIFT), pa_pfn;

		ret = vfio_pin_pages(viommu->sw_dev,
				     &vapfn, 1,
				     VFIO_DMA_MAP_FLAG_READ |
				     VFIO_DMA_MAP_FLAG_WRITE,
				     &pa_pfn);

		if (ret != 1) {
			/*sadly mdev api doesn't return an error*/
			ret = -EFAULT;

			_DBG(viommu->vctrl,
			     "vIOMMU: ADD RW IOVA %pad - pin failed\n",
			     &iova);
			goto unwind;
		}

		// new mapping needed
		if (!map || map->pfn + map_pages(map) != pa_pfn) {
			int node = viommu->hw_dev ?
				dev_to_node(viommu->hw_dev) : NUMA_NO_NODE;

			map = kzalloc_node(sizeof(*map), GFP_KERNEL, node);

			if (WARN_ON(!map)) {
				vfio_unpin_pages(viommu->sw_dev, &vapfn, 1);
				ret = -ENOMEM;
				goto unwind;
			}
			map->iova_start = iova + offset;
			map->iova_last = iova + offset + PAGE_SIZE - 1ULL;
			map->pfn = pa_pfn;
			map->host_iova = 0;
			list_add_tail(&map->link, &new_mappings_list);
		} else {
			// current map can be extended
			map->iova_last += PAGE_SIZE;
		}
	}

	// DMA mapping the pages
	list_for_each_entry_safe(map, tmp, &new_mappings_list, link) {
		if (viommu->hw_dev) {
			map->host_iova =
				dma_map_page(viommu->hw_dev,
					     pfn_to_page(map->pfn),
					     0,
					     map_len(map),
					     DMA_BIDIRECTIONAL);

			ret = dma_mapping_error(viommu->hw_dev, map->host_iova);
			if (ret) {
				_DBG(viommu->vctrl,
				     "vIOMMU: ADD RW IOVA %pad-%pad - DMA map failed\n",
				     &iova, &iova_end);
				goto unwind;
			}
		}

		nvme_mdev_viommu_dbg_dma_range(viommu, map, "ADD");
		list_del(&map->link);
		list_add_tail(&map->link, &viommu->maps_list);
		viommu_int_tree_insert(map, &viommu->maps_tree);
	}
	return 0;
unwind:
	list_for_each_entry_safe(map, tmp, &new_mappings_list, link) {
		nvme_mdev_viommu_unpin_pages(viommu, map->iova_start,
					     map_pages(map));

		list_del(&map->link);
		kfree(map);
	}
	nvme_mdev_viommu_remove(viommu, iova, size);
	return ret;
}

/* Removes a  range of user memory*/
int nvme_mdev_viommu_remove(struct nvme_mdev_viommu *viommu,
			    dma_addr_t iova,
			    u64 size)
{
	struct mem_mapping *map = NULL, *tmp;
	dma_addr_t last_iova = iova + (size) - 1ULL;
	LIST_HEAD(remove_list);
	int count = 0;

	/* find out all the relevant ranges */
	map = viommu_int_tree_iter_first(&viommu->maps_tree, iova, last_iova);
	while (map) {
		list_del(&map->link);
		list_add_tail(&map->link, &remove_list);
		map = viommu_int_tree_iter_next(map, iova, last_iova);
	}

	/* remove them */
	list_for_each_entry_safe(map, tmp, &remove_list, link) {
		count++;

		nvme_mdev_viommu_dbg_dma_range(viommu, map, "DEL");
		if (viommu->hw_dev)
			dma_unmap_page(viommu->hw_dev, map->host_iova,
				       map_len(map), DMA_BIDIRECTIONAL);

		nvme_mdev_viommu_unpin_pages(viommu, map->iova_start,
					     map_pages(map));

		viommu_int_tree_remove(map, &viommu->maps_tree);
		kfree(map);
	}
	return count;
}

/* Translate an IOVA to a physical address and read device bus address */
int nvme_mdev_viommu_translate(struct nvme_mdev_viommu *viommu,
			       dma_addr_t iova,
			       dma_addr_t *physical,
			       dma_addr_t *host_iova)
{
	struct mem_mapping *mapping;
	u64 offset;

	if (WARN_ON_ONCE(OFFSET_IN_PAGE(iova) != 0))
		return -EINVAL;

	mapping = viommu_int_tree_iter_first(&viommu->maps_tree,
					     iova, iova + PAGE_SIZE - 1);
	if (!mapping) {
		_DBG(viommu->vctrl,
		     "vIOMMU: translation of IOVA %pad failed\n", &iova);
		return -EFAULT;
	}

	WARN_ON(iova > mapping->iova_last);
	WARN_ON(OFFSET_IN_PAGE(mapping->iova_start) != 0);

	offset = iova - mapping->iova_start;
	*physical = PFN_PHYS(mapping->pfn) + offset;
	*host_iova = mapping->host_iova + offset;
	return 0;
}

/* map an IOVA to kernel address space  */
int nvme_mdev_viommu_create_kmap(struct nvme_mdev_viommu *viommu,
				 dma_addr_t iova, struct page_map *page)
{
	dma_addr_t host_iova;
	phys_addr_t physical;
	struct page *new_page;
	int ret;

	page->iova = iova;

	ret = nvme_mdev_viommu_translate(viommu, iova, &physical, &host_iova);
	if (ret)
		return ret;

	new_page = pfn_to_page(PHYS_PFN(physical));

	page->kmap = kmap(new_page);
	if (!page->kmap)
		return -ENOMEM;

	page->page = new_page;
	return 0;
}

/* update IOVA <-> kernel mapping. If fails, removes the previous mapping */
void nvme_mdev_viommu_update_kmap(struct nvme_mdev_viommu *viommu,
				  struct page_map *page)
{
	dma_addr_t host_iova;
	phys_addr_t physical;
	struct page *new_page;
	int ret;

	ret = nvme_mdev_viommu_translate(viommu, page->iova,
					 &physical, &host_iova);
	if (ret) {
		nvme_mdev_viommu_free_kmap(viommu, page);
		return;
	}

	new_page = pfn_to_page(PHYS_PFN(physical));
	if (new_page == page->page)
		return;

	nvme_mdev_viommu_free_kmap(viommu, page);

	page->kmap = kmap(new_page);
	if (!page->kmap)
		return;
	page->page = new_page;
}

/* unmap an IOVA to kernel address space  */
void nvme_mdev_viommu_free_kmap(struct nvme_mdev_viommu *viommu,
				struct page_map *page)
{
	if (page->page) {
		kunmap(page->page);
		page->page = NULL;
		page->kmap = NULL;
	}
}
