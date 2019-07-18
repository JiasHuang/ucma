#ifndef __UCMA_STRUCT_H__
#define __UCMA_STRUCT_H__

#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/list.h>

struct ucma_devctx {
	struct platform_device *pdev;
	struct device *dev;
	struct miscdevice miscdev;
	struct list_head list;
	struct mutex lock;
};

struct ucma_bufctx {
	struct ucma_devctx *devctx;
	struct device *dev;
	struct file *file;
	struct list_head list;
	struct list_head list_fh;
	u64 physaddr;
	u32 flags;
	u32 size;
	void *vaddr;
	dma_addr_t dma_handle;
	struct sg_table *sgt_base;
	atomic_t refcnt;
};

#endif
