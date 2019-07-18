#ifndef __UCMA_CORE_H__
#define __UCMA_CORE_H__

int ucma_querycap(struct ucma_devctx *devctx, struct ucma_caps *caps);
int ucma_alloc(struct ucma_devctx *devctx, struct file *file, struct ucma_reqbuf *reqbuf);
int ucma_free(struct ucma_devctx *devctx, struct ucma_reqbuf *reqbuf);
int ucma_expbuf(struct ucma_devctx *devctx, struct ucma_expbuf *expbuf);
int ucma_cleanup(struct ucma_devctx *devctx);
int ucma_mmap(struct ucma_devctx *devctx, struct vm_area_struct *vma);
int ucma_syncbuf(struct ucma_devctx *devctx, struct ucma_syncbuf *syncbuf);

int ucma_bufctx_put(struct ucma_bufctx *bufctx);
int ucma_bufctx_mmap(struct ucma_bufctx *bufctx, struct vm_area_struct *vma);

int ucma_test_dmafd(struct ucma_devctx *devctx, int dmafd);

#endif
