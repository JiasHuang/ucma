/*
 * Inspired by : videobuf2-dma-contig.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/dma-buf.h>

#include "ucma-interface.h"
#include "ucma-struct.h"
#include "ucma-ops.h"
#include "ucma-core.h"

static int ucma_probe(struct platform_device *pdev)
{
	int ret;
	struct ucma_devctx *devctx;

	devctx = devm_kzalloc(&pdev->dev, sizeof(*devctx), GFP_KERNEL);
	if (!devctx) {
		pr_err("%s: dev_kzalloc fails\n", __func__);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&devctx->list);

	mutex_init(&devctx->lock);

	devctx->pdev = pdev;
	devctx->dev = &pdev->dev;

	devctx->miscdev.minor = MISC_DYNAMIC_MINOR;
	devctx->miscdev.name = UCMA_DEV_NAME;
	devctx->miscdev.fops = &ucma_fops;

	ret = misc_register(&devctx->miscdev);
	if (ret) {
		pr_err("%s: misc_register fails\n", __func__);
		return ret;
	}

	/* finalize */
	platform_set_drvdata(pdev, devctx);

	return 0;
}

static int ucma_remove(struct platform_device *pdev)
{
	struct ucma_devctx *devctx;

	devctx = platform_get_drvdata(pdev);

	if (devctx) {
		ucma_cleanup(devctx);
		misc_deregister(&devctx->miscdev);
	}

	return 0;
}

static struct platform_driver ucma_drv = {
	.probe = ucma_probe,
	.remove = ucma_remove,
	.driver = {
		.name = UCMA_DEV_NAME,
	},
};

static struct platform_device ucma_dev = {
	.name = UCMA_DEV_NAME,
	.id = -1,
	.dev = {
		.dma_mask = &ucma_dev.dev.coherent_dma_mask,
		.coherent_dma_mask = DMA_BIT_MASK(32),
	},
};

static int __init ucma_drv_init(void)
{
	platform_device_register(&ucma_dev);
	platform_driver_register(&ucma_drv);
	return 0;
}

static void __exit ucma_drv_exit(void)
{
	platform_driver_unregister(&ucma_drv);
	platform_device_unregister(&ucma_dev);
}

module_init(ucma_drv_init);
module_exit(ucma_drv_exit);
MODULE_LICENSE("GPL");
