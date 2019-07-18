#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <asm/types.h>
#include <sys/mman.h>
#include <sys/time.h>

#include "ucma-interface.h"
#include "ucma-user-test-opts.h"

#define IF_ERR_EXIT(__cond) \
{ \
	int __ret = (__cond); \
	if (__ret) { \
		printf("%s:%d ret %d\n", __func__, __LINE__, __ret); \
		exit(-1); \
	} \
}

#define IF_FLAG(__cond, __flag) \
	((__cond)? __flag : 0)

#define elapsed(__t1, __t2) \
	((__t2.tv_sec - __t1.tv_sec) + (__t2.tv_usec - __t1.tv_usec) / 1000000.0)

#define measure(__codes) \
{ \
	struct timeval t1, t2; \
	gettimeofday(&t1, NULL); \
	(__codes); \
	gettimeofday(&t2, NULL); \
	printf("\'%s\' taken %lf sec\n", #__codes, elapsed(t1, t2)); \
}

#define highlight(__fmt, ...) \
{ \
	printf("\n[" __fmt "]\n\n", ##__VA_ARGS__); \
} \

static void test_read(void *ptr, int size)
{
	int i, ret = 0, *p32 = (int*)ptr, cnt = size >> 2;
	for (i=0; i<cnt; i++) ret += p32[i];
}

static void test_write(void *ptr, int size)
{
	int i, *p32 = (int*)ptr, cnt = size >> 2;
	for (i=0; i<cnt; i++) p32[i] = i;
}

static void test_mmap(char bCache, char bCleanup)
{
	int fd, ret, size;
	struct ucma_reqbuf reqbuf = {0};
	void *vaddr;

	highlight("test-mmap-%s-%s",
		bCache?  "cache" : "nocache",
		bCleanup? "cleanup" : "nocleanup");

	size = opts.size;

	fd = open(UCMA_DEV_PATH, O_RDWR | IF_FLAG(!bCache, O_SYNC));
	IF_ERR_EXIT(fd < 0);

	reqbuf.size = size;
	reqbuf.flags |= IF_FLAG(!bCleanup, UCMA_F_PUT_ON_CLOSE);
	ret = ioctl(fd, UCMA_IOC_ALLOC, &reqbuf);
	IF_ERR_EXIT(ret);

	printf("physaddr 0x%llx\n", reqbuf.physaddr);

	vaddr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, reqbuf.physaddr);
	IF_ERR_EXIT(vaddr == MAP_FAILED);

	printf("vaddr %p\n", vaddr);

	measure(test_write(vaddr, size));

	measure(test_read(vaddr, size));

	if (bCleanup) {
		munmap(vaddr, size);
		IF_ERR_EXIT(errno);

		ret = ioctl(fd, UCMA_IOC_FREE, &reqbuf);
		IF_ERR_EXIT(ret);

		close(fd);
	}
}

static void test_dmabuf(char bCache, char bCleanup)
{
	int fd, dmafd, ret, size;
	struct ucma_reqbuf reqbuf = {0};
	struct ucma_expbuf expbuf = {0};
	struct ucma_syncbuf syncbuf = {0};
	void *vaddr;

	highlight("test-dmabuf-%s-%s",
		bCache? "cache" : "nocache",
		bCleanup? "cleanup" : "nocleanup");

	size = opts.size;

	fd = open(UCMA_DEV_PATH, O_RDWR | IF_FLAG(!bCache, O_SYNC));
	IF_ERR_EXIT(fd < 0);

	reqbuf.size = size;
	reqbuf.flags |= IF_FLAG(!bCleanup, UCMA_F_PUT_ON_CLOSE);
	ret = ioctl(fd, UCMA_IOC_ALLOC, &reqbuf);
	IF_ERR_EXIT(ret);

	printf("physaddr 0x%llx\n", reqbuf.physaddr);

	expbuf.physaddr = reqbuf.physaddr;
	expbuf.flags = O_RDWR | IF_FLAG(!bCache, O_SYNC);
	ret = ioctl(fd, UCMA_IOC_EXPBUF, &expbuf);
	IF_ERR_EXIT(ret);

	dmafd = expbuf.fd;
	printf("dmafd %d\n", dmafd);

	ret = ioctl(fd, UCMA_IOC_TEST_DMAFD, &dmafd);
	IF_ERR_EXIT(ret);

	vaddr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, dmafd, 0);
	IF_ERR_EXIT(vaddr == MAP_FAILED);

	printf("vaddr %p\n", vaddr);

	measure(test_write(vaddr, size));

	if (bCache) {
		syncbuf.physaddr = reqbuf.physaddr;
		syncbuf.direction = UCMA_DIR_TO_DEVICE;
		measure(ret = ioctl(fd, UCMA_IOC_SYNCBUF, &syncbuf));
		IF_ERR_EXIT(ret);
	}

	if (bCache) {
		syncbuf.physaddr = reqbuf.physaddr;
		syncbuf.direction = UCMA_DIR_FROM_DEVICE;
		measure(ret = ioctl(fd, UCMA_IOC_SYNCBUF, &syncbuf));
		IF_ERR_EXIT(ret);
	}

	measure(test_read(vaddr, size));

	if (bCleanup) {
		munmap(vaddr, size);
		IF_ERR_EXIT(errno);

		close(dmafd);

		ret = ioctl(fd, UCMA_IOC_FREE, &reqbuf);
		IF_ERR_EXIT(ret);

		close(fd);
	}
}

int main(int argc, char *argv[])
{
	parseArgs(&opts, argc, argv);

	measure(test_mmap(0, 0));
	measure(test_mmap(1, 0));
	measure(test_dmabuf(1, 0));

	return 0;
}

