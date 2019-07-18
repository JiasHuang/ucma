/*
 * Inspired by : videobuf2-dma-contig.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/pageremap.h>

#include "ucma-interface.h"
#include "ucma-struct.h"
#include "ucma-core.h"
#include "ucma-dmabuf-ops.h"

static struct ucma_bufctx* get_bufctx_by_physaddr(struct ucma_devctx *devctx, u64 physaddr)
{
	struct ucma_bufctx *bufctx;

	list_for_each_entry (bufctx, &devctx->list, list) {
		if (bufctx->physaddr == physaddr)
			return bufctx;
	}

	return NULL;
}

static void vm_ops_open(struct vm_area_struct *vma)
{
	struct ucma_bufctx *bufctx = vma->vm_private_data;

	mutex_lock(&bufctx->devctx->lock);
	atomic_inc(&bufctx->refcnt);
	mutex_unlock(&bufctx->devctx->lock);
}

static void vm_ops_close(struct vm_area_struct *vma)
{
	struct ucma_bufctx *bufctx = vma->vm_private_data;

	mutex_lock(&bufctx->devctx->lock);
	ucma_bufctx_put(bufctx);
	mutex_unlock(&bufctx->devctx->lock);
}

static const struct vm_operations_struct ucma_vm_ops = {
	.open = vm_ops_open,
	.close = vm_ops_close,
};

static struct sg_table* get_base_sgt(struct ucma_bufctx *bufctx)
{
	int ret;
	struct sg_table *sgt;

	sgt = kmalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt) {
		dev_err(bufctx->dev, "failed to alloc sg table\n");
		return NULL;
	}

	ret = dma_get_sgtable(bufctx->dev, sgt, bufctx->vaddr, bufctx->dma_handle,
		bufctx->size);
	if (ret < 0) {
		dev_err(bufctx->dev, "failed to get scatterlist from DMA API\n");
		kfree(sgt);
		return NULL;
	}

	return sgt;
}

static int export_dmabuf(struct ucma_bufctx *bufctx, u32 flags)
{
	int fd;
	struct dma_buf *dmabuf;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	if (!bufctx->sgt_base) {
		bufctx->sgt_base = get_base_sgt(bufctx);
	}

	exp_info.ops = &ucma_dmabuf_ops;
	exp_info.size = bufctx->size;
	exp_info.flags = flags;
	exp_info.priv = bufctx;

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		pr_err("%s: dma_buf_export fail\n", __func__);
		return -1;
	}

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0) {
		dma_buf_put(dmabuf);
		pr_err("%s: dma_buf_fd fail\n", __func__);
		return -1;
	}

	atomic_inc(&bufctx->refcnt);

	return fd;
}

int ucma_querycap(struct ucma_devctx *devctx, struct ucma_caps *caps)
{
	memset(caps, 0, sizeof(*caps));
	caps->caps = UCMA_CAP_CMABUF | UCMA_CAP_DMABUF;
	return 0;
}

int ucma_alloc(struct ucma_devctx *devctx, struct file *file, struct ucma_reqbuf *reqbuf)
{
	struct ucma_bufctx *bufctx = NULL;

	bufctx = kzalloc(sizeof(*bufctx), GFP_KERNEL);
	if (!bufctx) {
		pr_err("%s: kzalloc fail\n", __func__);
		return -ENOMEM;
	}

	bufctx->devctx = devctx;
	bufctx->dev = devctx->dev;
	bufctx->size = roundup(reqbuf->size, PAGE_SIZE);
	bufctx->flags = reqbuf->flags;
	bufctx->file = file;

	bufctx->vaddr = dma_alloc_coherent(bufctx->dev, bufctx->size, &bufctx->dma_handle, GFP_KERNEL);
	if (IS_ERR_OR_NULL(bufctx->vaddr)) {
		kfree(bufctx);
		pr_err("%s: dma_alloc_coherent fail\n", __func__);
		return -ENOMEM;
	}

	atomic_inc(&bufctx->refcnt);
	bufctx->physaddr = virt_to_phys(bufctx->vaddr);
	list_add(&bufctx->list, &devctx->list);

	reqbuf->physaddr = bufctx->physaddr;

	pr_info("%s: dma_handle 0x%08x physaddr 0x%llx size %d\n", __func__,
		bufctx->dma_handle, bufctx->physaddr, bufctx->size);

	return 0;
}

int ucma_free(struct ucma_devctx *devctx, struct ucma_reqbuf *reqbuf)
{
	struct ucma_bufctx *bufctx;

	bufctx = get_bufctx_by_physaddr(devctx, reqbuf->physaddr);
	if (!bufctx) {
		pr_err("%s: no bufctx with physaddr 0x%llx\n", __func__, reqbuf->physaddr);
		return -EINVAL;
	}

	/* remove UCMA_F_PUT_ON_CLOSE */
	bufctx->flags &= ~UCMA_F_PUT_ON_CLOSE;

	return ucma_bufctx_put(bufctx);
}

int ucma_expbuf(struct ucma_devctx *devctx, struct ucma_expbuf *expbuf)
{
	struct ucma_bufctx *bufctx;

	bufctx = get_bufctx_by_physaddr(devctx, expbuf->physaddr);
	if (!bufctx) {
		pr_err("%s: no bufctx with physaddr 0x%llx\n", __func__, expbuf->physaddr);
		return -EINVAL;
	}

	expbuf->fd = export_dmabuf(bufctx, expbuf->flags);
	if (expbuf->fd < 0) {
		pr_err("%s: fail to export dmabuf\n", __func__);
		return -EFAULT;
	}

	pr_info("%s: physaddr 0x%llx flags 0x%x fd %d\n", __func__,
		expbuf->physaddr, expbuf->flags, expbuf->fd);

	return 0;
}

int ucma_cleanup(struct ucma_devctx *devctx)
{
	struct ucma_bufctx *bufctx, *bufctx_tmp;

	list_for_each_entry_safe (bufctx, bufctx_tmp, &devctx->list, list) {
		pr_info("%s: physaddr 0x%llx size %d refcnt %d\n", __func__,
			bufctx->physaddr, bufctx->size, atomic_read(&bufctx->refcnt));
		dma_free_coherent(bufctx->dev, bufctx->size, bufctx->vaddr, bufctx->dma_handle);
		list_del(&bufctx->list);
		kfree(bufctx);
	}

	return 0;
}

int ucma_mmap(struct ucma_devctx *devctx, struct vm_area_struct *vma)
{
	u64 addr;
	int size;
	struct ucma_bufctx *bufctx;

	addr = vma->vm_pgoff << PAGE_SHIFT;
	size = vma->vm_end - vma->vm_start;

	bufctx = get_bufctx_by_physaddr(devctx, addr);
	if (!bufctx) {
		pr_err("%s: no bufctx with physaddr 0x%llx\n", __func__, addr);
		return -EINVAL;
	}

	if (size > bufctx->size) {
		pr_err("%s: illegal size %d > %d\n", __func__, size, bufctx->size);
		return -EPERM;
	}

	return ucma_bufctx_mmap(bufctx, vma);
}

int ucma_syncbuf(struct ucma_devctx *devctx, struct ucma_syncbuf *syncbuf)
{
	struct ucma_bufctx *bufctx;

	bufctx = get_bufctx_by_physaddr(devctx, syncbuf->physaddr);
	if (!bufctx) {
		pr_err("%s: no bufctx with physaddr 0x%llx\n", __func__, syncbuf->physaddr);
		return -EINVAL;
	}

	switch (syncbuf->direction) {
		case UCMA_DIR_TO_DEVICE:
			dma_sync_single_for_device(devctx->dev,
				bufctx->dma_handle, bufctx->size, DMA_TO_DEVICE);
			break;
		case UCMA_DIR_FROM_DEVICE:
			dma_sync_single_for_cpu(devctx->dev,
				bufctx->dma_handle, bufctx->size, DMA_FROM_DEVICE);
			break;
	}

	return 0;
}

int ucma_bufctx_put(struct ucma_bufctx *bufctx)
{
	if (!atomic_dec_and_test(&bufctx->refcnt))
		return 0;

	if (bufctx->sgt_base) {
		sg_free_table(bufctx->sgt_base);
		kfree(bufctx->sgt_base);
	}

	dma_free_coherent(bufctx->dev, bufctx->size, bufctx->vaddr, bufctx->dma_handle);
	list_del(&bufctx->list);
	kfree(bufctx);

	return 0;
}

int ucma_bufctx_mmap(struct ucma_bufctx *bufctx, struct vm_area_struct *vma)
{
	int ret;

	if (vma->vm_file && vma->vm_file->f_flags & O_SYNC) {
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	}

	/* dma_mmap_* uses vm_pgoff as in-buffer offset, but we want to map whole buffer */
	vma->vm_pgoff = 0;

	ret = dma_mmap_coherent(bufctx->dev, vma, bufctx->vaddr,
		bufctx->dma_handle, bufctx->size);
	if (ret) {
		pr_err("%s: dma_mmap_coherent ret %d\n", __func__, ret);
		return ret;
	}

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_private_data = bufctx;
	vma->vm_ops = &ucma_vm_ops;

	atomic_inc(&bufctx->refcnt);

	pr_info("%s: dma_handle 0x%08x size %d\n", __func__, bufctx->dma_handle, bufctx->size);

	return 0;
}

int ucma_test_dmafd(struct ucma_devctx *devctx, int dmafd)
{
	struct dma_buf *dmabuf = NULL;
	struct dma_buf_attachment *attach = NULL;
	struct sg_table *sgt = NULL;

	dmabuf = dma_buf_get(dmafd);
	if (IS_ERR_OR_NULL(dmabuf)) goto err;

	attach = dma_buf_attach(dmabuf, devctx->dev);
	if (IS_ERR(attach)) goto err;

	sgt = dma_buf_map_attachment(attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(sgt)) goto err;

	pr_info("%s: nents %d sg_dma_addr 0x%08x size %d\n", __func__,
		sgt->nents, sg_dma_address(sgt->sgl), sg_dma_len(sgt->sgl));

	dma_buf_unmap_attachment(attach, sgt, DMA_BIDIRECTIONAL);
	dma_buf_detach(dmabuf, attach);
	dma_buf_put(dmabuf);

	return 0;

err:
	pr_err("%s: dmabuf %p attach %p sgt %p\n", __func__, dmabuf, attach, sgt);

	if (attach && sgt) dma_buf_unmap_attachment(attach, sgt, DMA_BIDIRECTIONAL);
	if (dmabuf && attach) dma_buf_detach(dmabuf, attach);
	if (dmabuf) dma_buf_put(dmabuf);

	return -1;
}

