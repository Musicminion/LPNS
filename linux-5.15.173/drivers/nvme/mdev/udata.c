// SPDX-License-Identifier: GPL-2.0+
/*
 * User (guest) data access routines
 * Implementation of PRP iterator in user memory
 * Copyright (c) 2019 - Maxim Levitsky
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/mdev.h>
#include <linux/nvme.h>
#include "priv.h"

#define MAX_PRP ((PAGE_SIZE / sizeof(__le64)) - 1)

/* Setup up a new PRP iterator */
void nvme_mdev_udata_iter_setup(struct nvme_mdev_viommu *viommu,
				struct nvme_ext_data_iter *iter)
{
	iter->viommu = viommu;
	iter->count = 0;
	iter->next = NULL;
	iter->release = NULL;
}

/* Load a new prp list into the iterator. Internal*/
static int nvme_mdev_udata_iter_load_prplist(struct nvme_ext_data_iter *iter,
					     dma_addr_t iova)
{
	dma_addr_t  data_iova;
	int ret;
	__le64 *map;

	/* map the prp list*/
	ret = nvme_mdev_viommu_create_kmap(iter->viommu,
					   PAGE_ADDRESS(iova),
					   &iter->uprp.page);
	if (ret)
		return ret;

	iter->uprp.index = OFFSET_IN_PAGE(iova) / (sizeof(__le64));

	/* read its first entry and check its alignment */
	map = iter->uprp.page.kmap;
	data_iova = le64_to_cpu(map[iter->uprp.index]);

	if (OFFSET_IN_PAGE(data_iova) != 0) {
		nvme_mdev_viommu_free_kmap(iter->viommu, &iter->uprp.page);
		return -EINVAL;
	}

	/* translate the entry to complete the setup*/
	ret =  nvme_mdev_viommu_translate(iter->viommu, data_iova,
					  &iter->physical, &iter->host_iova);
	if (ret)
		nvme_mdev_viommu_free_kmap(iter->viommu, &iter->uprp.page);

	return ret;
}

/* ->next function when iterator points to prp list*/
static int nvme_mdev_udata_iter_next_prplist(struct nvme_ext_data_iter *iter)
{
	dma_addr_t iova;
	int ret;
	__le64 *map = iter->uprp.page.kmap;

	if (WARN_ON(iter->count <= 0))
		return 0;

	if (--iter->count == 0) {
		nvme_mdev_viommu_free_kmap(iter->viommu, &iter->uprp.page);
		return 0;
	}

	iter->uprp.index++;

	if (iter->uprp.index < MAX_PRP || iter->count == 1) {
		// advance over next pointer in current prp list
		// these pointers must be page aligned
		iova = le64_to_cpu(map[iter->uprp.index]);
		if (OFFSET_IN_PAGE(iova) != 0)
			return -EINVAL;

		ret  = nvme_mdev_viommu_translate(iter->viommu, iova,
						  &iter->physical,
						  &iter->host_iova);
		if (ret)
			nvme_mdev_viommu_free_kmap(iter->viommu,
						   &iter->uprp.page);
		return ret;
	}

	/* switch to next prp list. it must be page aligned as well*/
	iova = le64_to_cpu(map[MAX_PRP]);

	if (OFFSET_IN_PAGE(iova) != 0)
		return -EINVAL;

	nvme_mdev_viommu_free_kmap(iter->viommu, &iter->uprp.page);
	return nvme_mdev_udata_iter_load_prplist(iter, iova);
}

/* ->next function when iterator points to user data pointer*/
static int nvme_mdev_udata_iter_next_dptr(struct nvme_ext_data_iter *iter)
{
	dma_addr_t  iova;

	if (WARN_ON(iter->count <= 0))
		return 0;

	if (--iter->count == 0)
		return 0;

	/* we will be called only once to deal with the second
	 * pointer in the data pointer
	 */
	iova = le64_to_cpu(iter->dptr->prp2);

	if (iter->count == 1) {
		/* only need to read one more entry, meaning
		 * the 2nd entry of the dptr.
		 * It must be page aligned
		 */
		if (OFFSET_IN_PAGE(iova) != 0)
			return -EINVAL;
		return nvme_mdev_viommu_translate(iter->viommu, iova,
						  &iter->physical,
						  &iter->host_iova);
	} else {
		/*
		 * Second dptr entry is prp pointer, and it might not
		 * be page aligned (but QWORD aligned at least)
		 */
		if (iova & 0x7ULL)
			return -EINVAL;
		iter->next = nvme_mdev_udata_iter_next_prplist;
		return nvme_mdev_udata_iter_load_prplist(iter, iova);
	}
}

/* Set prp list iterator to point to data pointer found in NVME command */
int nvme_mdev_udata_iter_set_dptr(struct nvme_ext_data_iter *it,
				  const union nvme_data_ptr *dptr, u64 size)
{
	int ret;
	u64 prp1 = le64_to_cpu(dptr->prp1);
	dma_addr_t iova = PAGE_ADDRESS(prp1);
	unsigned int page_offset = OFFSET_IN_PAGE(prp1);

	/* first dptr pointer must be at least DWORD aligned*/
	if (page_offset & 0x3)
		return -EINVAL;

	it->dptr = dptr;
	it->next = nvme_mdev_udata_iter_next_dptr;
	it->count = DIV_ROUND_UP_ULL(size + page_offset, PAGE_SIZE);

	ret = nvme_mdev_viommu_translate(it->viommu, iova,
					 &it->physical, &it->host_iova);
	if (ret)
		return ret;

	it->physical += page_offset;
	it->host_iova += page_offset;
	return 0;
}

/* ->next function when iterator points to kernel memory buffer */
static int nvme_mdev_kdata_iter_next(struct nvme_ext_data_iter *it)
{
	if (WARN_ON(it->count <= 0))
		return 0;

	if (--it->count == 0)
		return 0;

	it->physical = PAGE_ADDRESS(it->physical) + PAGE_SIZE;
	it->host_iova = PAGE_ADDRESS(it->host_iova) + PAGE_SIZE;
	return 0;
}

/* ->release function for kdata iterator to free it after use */
static void nvme_mdev_kdata_iter_free(struct nvme_ext_data_iter *it)
{
	struct device *dma_dev = it->viommu->hw_dev;

	if (dma_dev)
		dma_free_coherent(dma_dev, it->kmem.size,
				  it->kmem.data, it->kmem.dma_addr);
	else
		kfree(it->kmem.data);
	kfree(it);
}

/* allocate a kernel data buffer with read iterator for nvme host device */
struct nvme_ext_data_iter *
nvme_mdev_kdata_iter_alloc(struct nvme_mdev_viommu *viommu, unsigned int size)
{
	struct nvme_ext_data_iter *it;

	it = kzalloc(sizeof(*it), GFP_KERNEL);
	if (!it)
		return NULL;

	it->viommu = viommu;
	it->kmem.size = size;
	if (viommu->hw_dev) {
		it->kmem.data = dma_alloc_coherent(viommu->hw_dev, size,
						   &it->kmem.dma_addr,
						   GFP_KERNEL);
	} else {
		it->kmem.data = kzalloc(size, GFP_KERNEL);
		it->kmem.dma_addr = 0;
	}

	if (!it->kmem.data) {
		kfree(it);
		return NULL;
	}

	it->physical = virt_to_phys(it->kmem.data);
	it->host_iova = it->kmem.dma_addr;

	it->count = DIV_ROUND_UP(size + OFFSET_IN_PAGE(it->physical),
				 PAGE_SIZE);

	it->next = nvme_mdev_kdata_iter_next;
	it->release = nvme_mdev_kdata_iter_free;
	return it;
}

/* copy data from user data iterator to a kernel buffer */
int nvme_mdev_read_from_udata(void *dst, struct nvme_ext_data_iter *srcit,
			      u64 size)
{
	int ret;
	unsigned int srcoffset, chunk_size;

	while (srcit->count && size > 0) {
		struct page *page = pfn_to_page(PHYS_PFN(srcit->physical));
		void *src = kmap(page);

		if (!src)
			return -ENOMEM;

		srcoffset = OFFSET_IN_PAGE(srcit->physical);
		chunk_size = min(size, (u64)PAGE_SIZE - srcoffset);

		memcpy(dst, src + srcoffset, chunk_size);
		dst += chunk_size;
		size -= chunk_size;
		kunmap(page);

		ret = srcit->next(srcit);
		if (ret)
			return ret;
	}
	WARN_ON(size > 0);
	return 0;
}

/* copy data from kernel buffer to user data iterator */
int nvme_mdev_write_to_udata(struct nvme_ext_data_iter *dstit, void *src,
			     u64 size)
{
	int ret, dstoffset, chunk_size;

	while (dstit->count && size > 0) {
		struct page *page = pfn_to_page(PHYS_PFN(dstit->physical));
		void *dst = kmap(page);

		if (!dst)
			return -ENOMEM;

		dstoffset = OFFSET_IN_PAGE(dstit->physical);
		chunk_size = min(size, (u64)PAGE_SIZE - dstoffset);

		memcpy(dst + dstoffset, src, chunk_size);
		src += chunk_size;
		size -= chunk_size;
		kunmap(page);

		ret = dstit->next(dstit);
		if (ret)
			return ret;
	}
	WARN_ON(size > 0);
	return 0;
}

/* Set prp list iterator to point to prp list found in create queue command */
static int
nvme_mdev_udata_iter_set_queue_prplist(struct nvme_mdev_viommu *viommu,
				       struct nvme_ext_data_iter *iter,
				       dma_addr_t iova, unsigned int size)
{
	if (iova & ~PAGE_MASK)
		return -EINVAL;

	nvme_mdev_udata_iter_setup(viommu, iter);
	iter->count = DIV_ROUND_UP(size, PAGE_SIZE);
	iter->next = nvme_mdev_udata_iter_next_prplist;
	return nvme_mdev_udata_iter_load_prplist(iter, iova);
}

/* Map an SQ/CQ queue (contiguous in guest physical memory) */
static int nvme_mdev_queue_getpages_contiguous(struct nvme_mdev_viommu *viommu,
					       dma_addr_t iova,
					       struct page **pages,
					       unsigned int npages)
{
	int ret;
	unsigned int i;

	dma_addr_t host_page_iova;
	phys_addr_t physical;

	for (i = 0 ; i < npages; i++) {
		ret = nvme_mdev_viommu_translate(viommu, iova + (PAGE_SIZE * i),
						 &physical,
						 &host_page_iova);
		if (ret)
			return ret;
		pages[i] = pfn_to_page(PHYS_PFN(physical));
	}
	return 0;
}

/* Map an SQ/CQ queue (non contiguous in guest physical memory) */
static int nvme_mdev_queue_getpages_prplist(struct nvme_mdev_viommu *viommu,
					    dma_addr_t iova,
					    struct page **pages,
					    unsigned int npages)
{
	int ret, i = 0;
	struct nvme_ext_data_iter uprpit;

	ret = nvme_mdev_udata_iter_set_queue_prplist(viommu,
						     &uprpit, iova,
						     npages * PAGE_SIZE);
	if (ret)
		return ret;

	while (uprpit.count && i < npages) {
		pages[i++] = pfn_to_page(PHYS_PFN(uprpit.physical));
		ret = uprpit.next(&uprpit);
		if (ret)
			return ret;
	}
	return 0;
}

/* map a SQ/CQ queue to host physical memory */
void *nvme_mdev_udata_queue_vmap(struct nvme_mdev_viommu *viommu,
				 dma_addr_t iova,
				 unsigned int size,
				 bool cont)
{
	int ret;
	unsigned int npages;
	void *map;
	struct page **pages;

	// queue must be page aligned
	if (OFFSET_IN_PAGE(iova) != 0)
		return ERR_PTR(-EINVAL);

	npages = DIV_ROUND_UP(size, PAGE_SIZE);
	pages = kcalloc(npages, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return ERR_PTR(-ENOMEM);

	ret = cont ?
		nvme_mdev_queue_getpages_contiguous(viommu, iova, pages, npages)
		: nvme_mdev_queue_getpages_prplist(viommu, iova, pages, npages);

	if (ret) {
		map = ERR_PTR(ret);
		goto out;
	}

	map =  vmap(pages, npages, VM_MAP, PAGE_KERNEL);
	if (!map)
		map = ERR_PTR(-ENOMEM);
out:
	kfree(pages);
	return map;
}
