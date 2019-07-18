/*
 * Inspired by : videobuf2-dma-contig.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include "ucma-interface.h"
#include "ucma-struct.h"
#include "ucma-core.h"

#define file_to_devctx(file) (container_of(file->private_data, struct ucma_devctx, miscdev))

static int fops_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int fops_release(struct inode *inode, struct file *file)
{
	struct ucma_devctx *devctx = file_to_devctx(file);
	struct ucma_bufctx *bufctx, *bufctx_tmp;

	mutex_lock(&devctx->lock);
	list_for_each_entry_safe (bufctx, bufctx_tmp, &devctx->list, list) {
		if ((bufctx->flags & UCMA_F_PUT_ON_CLOSE) && bufctx->file == file) {
			ucma_bufctx_put(bufctx);
		}
	}
	mutex_unlock(&devctx->lock);

	return 0;
}

static long fops_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = -1, ioc_dir, ioc_size;
	struct ucma_devctx *devctx = file_to_devctx(file);
	char sbuf[128];
	void *mbuf = NULL, *parg = NULL;

	ioc_dir = _IOC_DIR(cmd);
	ioc_size = _IOC_SIZE(cmd);

	if (ioc_dir != _IOC_NONE) {
		if (ioc_size  <= sizeof(sbuf))
			parg = sbuf;
		else {
			mbuf = kmalloc(ioc_size, GFP_KERNEL);
			if (!mbuf)
				return -ENOMEM;
			parg = mbuf;
		}
		if (ioc_dir & _IOC_WRITE) {
			if (copy_from_user(parg, (void __user *)arg, ioc_size)) {
				ret = -EFAULT;
				goto out;
			}
		}
	}

	switch (cmd) {
		case UCMA_IOC_QUERYCAP:
			ret = ucma_querycap(devctx, parg);
			break;
		case UCMA_IOC_ALLOC:
			mutex_lock(&devctx->lock);
			ret = ucma_alloc(devctx, file, parg);
			mutex_unlock(&devctx->lock);
			break;
		case UCMA_IOC_FREE:
			mutex_lock(&devctx->lock);
			ret = ucma_free(devctx, parg);
			mutex_unlock(&devctx->lock);
			break;
		case UCMA_IOC_EXPBUF:
			mutex_lock(&devctx->lock);
			ret = ucma_expbuf(devctx, parg);
			mutex_unlock(&devctx->lock);
			break;
		case UCMA_IOC_SYNCBUF:
			ret = ucma_syncbuf(devctx, parg);
			break;
		case UCMA_IOC_TEST_DMAFD:
			ret = ucma_test_dmafd(devctx, *(int*)parg);
			break;
		default:
			ret = -EINVAL;
			pr_err("%s: unknown cmd %d\n", __func__, cmd);
			break;
	}

	if (ret)
		goto out;

	if (ioc_dir & _IOC_READ) {
		if (copy_to_user((void __user *)arg, parg, ioc_size)) {
			ret = -EFAULT;
			goto out;
		}
	}

out:

	if (mbuf) kfree(mbuf);

	return ret;
}

static int fops_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret;
	struct ucma_devctx *devctx = file_to_devctx(file);

	mutex_lock(&devctx->lock);
	ret = ucma_mmap(devctx, vma);
	mutex_unlock(&devctx->lock);

	return ret;
}

const struct file_operations ucma_fops = {
	.owner = THIS_MODULE,
	.open = fops_open,
	.release = fops_release,
	.unlocked_ioctl = fops_unlocked_ioctl,
	.mmap = fops_mmap,
};

