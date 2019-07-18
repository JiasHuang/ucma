include env.mk

CFLAGS = -Werror -Wall
LDFLAGS =

ifneq ($(SYSROOT),)
CFLAGS += --sysroot=$(SYSROOT)
LDFLAGS += --sysroot=$(SYSROOT)
endif

INCS =
LIBS =
OPTS = ucma-user-test-opts.h
OBJS = ucma-user-test.o
TARGET = ucma-user-test

include $(filter-out env.mk, $(wildcard *.mk))

all: $(OPTS) $(TARGET)

%.h: options.py %.xml
	./options.py -o $@ -i $(patsubst %.h, %.xml, $@)

ucma-user-test: $(OBJS)
	$(CROSS_COMPILE)gcc $(LDFLAGS) $(LIBS) -o $@ $^

%.o: %.c
	$(CROSS_COMPILE)gcc $(CFLAGS) $(INCS) -c $<

clean:
	rm -f *.o $(TARGET)
