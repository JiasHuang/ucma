#ifndef __UCMA_INTERFACE_H__
#define __UCMA_INTERFACE_H__

#define UCMA_DEV_NAME "ucma"
#define UCMA_DEV_PATH "/dev/"UCMA_DEV_NAME

#define UCMA_CAP_CMABUF 0x00000001
#define UCMA_CAP_DMABUF 0x00000002

#define UCMA_F_PUT_ON_CLOSE 0x00000001

#define UCMA_DIR_TO_DEVICE 1
#define UCMA_DIR_FROM_DEVICE 2

struct ucma_caps {
	__u32 caps;
};

struct ucma_reqbuf {
	__u32 size;
	__u32 flags;
	__u64 physaddr; /* set by driver */
};

struct ucma_expbuf {
	__u64 physaddr;
	__u32 flags; /* flags for the newly created file (i.e. O_CLOEXEC/O_RDWR/...) */
	__s32 fd; /* The DMABUF file descriptor associated with a buffer. Set by the driver. */
};

struct ucma_syncbuf {
	__u64 physaddr;
	__u32 direction;
};

#define UCMA_IOC_QUERYCAP	_IOR('U', 0, struct ucma_caps)
#define UCMA_IOC_ALLOC		_IOWR('U', 1, struct ucma_reqbuf)
#define UCMA_IOC_FREE		_IOW('U', 2, struct ucma_reqbuf)
#define UCMA_IOC_EXPBUF		_IOWR('U', 3, struct ucma_expbuf)
#define UCMA_IOC_SYNCBUF	_IOW('U', 4, struct ucma_syncbuf)

#define UCMA_IOC_TEST_DMAFD	_IOW('U', 1000, int)

#endif
