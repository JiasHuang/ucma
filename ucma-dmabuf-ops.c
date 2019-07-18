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

struct dmabuf_attach_ctx {
	struct sg_table sgt;
	enum dma_data_direction dir;
};

static int dmabuf_ops_attach(struct dma_buf *dmabuf, struct device *dev,
	struct dma_buf_attachment *attach)
{
	int i, ret;
	struct dmabuf_attach_ctx *actx;
	struct scatterlist *rd, *wr;
	struct sg_table *sgt;
	struct ucma_bufctx *bufctx = dmabuf->priv;

	actx = kzalloc(sizeof(*actx), GFP_KERNEL);
	if (!actx)
		return -ENOMEM;

	sgt = &actx->sgt;
	/* Copy the buf->base_sgt scatter list to the attachment, as we can't
	 * map the same scatter list to multiple attachments at the same time.
	 */
	ret = sg_alloc_table(sgt, bufctx->sgt_base->orig_nents, GFP_KERNEL);
	if (ret) {
		kfree(actx);
		return -ENOMEM;
	}

	rd = bufctx->sgt_base->sgl;
	wr = sgt->sgl;
	for (i = 0; i < sgt->orig_nents; ++i) {
		sg_set_page(wr, sg_page(rd), rd->length, rd->offset);
		rd = sg_next(rd);
		wr = sg_next(wr);
	}

	actx->dir = DMA_NONE;
	attach->priv = actx;

	return 0;
}

static void dmabuf_ops_detach(struct dma_buf *dmabuf, struct dma_buf_attachment *attach)
{
	struct dmabuf_attach_ctx *actx = attach->priv;
	struct sg_table *sgt;

	if (!actx)
		return;

	sgt = &actx->sgt;

	/* release the scatterlist cache */
	if (actx->dir != DMA_NONE) {
		dma_unmap_sg(attach->dev, sgt->sgl, sgt->orig_nents, actx->dir);
	}

	sg_free_table(sgt);
	kfree(actx);
	attach->priv = NULL;
}

static struct sg_table *dmabuf_ops_map(
	struct dma_buf_attachment *attach, enum dma_data_direction dir)
{
	struct dmabuf_attach_ctx *actx = attach->priv;
	/* stealing dmabuf mutex to serialize map/unmap operations */
	struct mutex *lock = &attach->dmabuf->lock;
	struct sg_table *sgt;

	mutex_lock(lock);

	sgt = &actx->sgt;
	/* return previously mapped sg table */
	if (actx->dir == dir) {
		mutex_unlock(lock);
		return sgt;
	}

	/* release any previous cache */
	if (actx->dir != DMA_NONE) {
		dma_unmap_sg(attach->dev, sgt->sgl, sgt->orig_nents, actx->dir);
		actx->dir = DMA_NONE;
	}

	/* mapping to the client with new direction */
	sgt->nents = dma_map_sg(attach->dev, sgt->sgl, sgt->orig_nents, dir);
	if (!sgt->nents) {
		pr_err("%s: failed to map scatterlist\n", __func__);
		mutex_unlock(lock);
		return ERR_PTR(-EIO);
	}

	actx->dir = dir;

	mutex_unlock(lock);

	return sgt;
}

static void dmabuf_ops_unmap(struct dma_buf_attachment *attach,
	struct sg_table *sgt, enum dma_data_direction dir)
{
	/* nothing to be done here */
}

static int dmabuf_ops_begin_cpu_access(struct dma_buf *dmabuf, size_t start,
	size_t len, enum dma_data_direction dir)
{
	pr_info("%s\n", __func__);
	return 0;
}

static void dmabuf_ops_end_cpu_access(struct dma_buf *dmabuf, size_t start,
	size_t len, enum dma_data_direction dir)
{
	pr_info("%s\n", __func__);
}

static void* dmabuf_ops_kmap(struct dma_buf *dmabuf, unsigned long offset)
{
	struct ucma_bufctx *bufctx = dmabuf->priv;
	return bufctx->vaddr + offset * PAGE_SIZE;
}

static void* dmabuf_ops_vmap(struct dma_buf *dmabuf)
{
	struct ucma_bufctx *bufctx = dmabuf->priv;
	return bufctx->vaddr;
}

static void dmabuf_ops_release(struct dma_buf *dmabuf)
{
	struct ucma_bufctx *bufctx = dmabuf->priv;

	mutex_lock(&bufctx->devctx->lock);
	ucma_bufctx_put(dmabuf->priv);
	mutex_unlock(&bufctx->devctx->lock);
}

static int dmabuf_ops_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	int ret;
	struct ucma_bufctx *bufctx = dmabuf->priv;

	mutex_lock(&bufctx->devctx->lock);
	ret = ucma_bufctx_mmap(dmabuf->priv, vma);
	mutex_unlock(&bufctx->devctx->lock);

	return ret;
}

const struct dma_buf_ops ucma_dmabuf_ops = {
	.attach = dmabuf_ops_attach,
	.detach = dmabuf_ops_detach,
	.map_dma_buf = dmabuf_ops_map,
	.unmap_dma_buf = dmabuf_ops_unmap,
	.begin_cpu_access = dmabuf_ops_begin_cpu_access,
	.end_cpu_access = dmabuf_ops_end_cpu_access,
	.kmap = dmabuf_ops_kmap,
	.kmap_atomic = dmabuf_ops_kmap,
	.vmap = dmabuf_ops_vmap,
	.mmap = dmabuf_ops_mmap,
	.release = dmabuf_ops_release,
};

