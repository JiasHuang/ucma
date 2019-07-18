
CONFIG_UCMA ?= m

ccflags-y += -Werror

ucma-objs := \
	ucma-drv-no-dev-tree.o \
	ucma-ops.o \
	ucma-core.o \
	ucma-dmabuf-ops.o \

obj-$(CONFIG_UCMA) = ucma.o
