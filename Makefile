DBG_OUTPUT_FILENAME := $("/log")

CFLAGS += -Wall -D__BM_PRE_READ__ -D__BM_SYNC_BH_WRITEBACK__


ifneq ($(KERNELRELEASE),)

CFLAGS += -g
obj-m := bm.o 
bm-objs := init.o bm_insert.o bm_read.o driver.o mapper.o sche.o
else

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CFLAGS += -g -fPIC

defualt: 
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean: 
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean

endif	