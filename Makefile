TARGET_MODULE = syscallmonitor
obj-m = $(TARGET_MODULE).o

# KERNEL_BUILD_DIR_PATH var is to select any installed kernel version from any directory.
# If no such exists, one of the preinstalled kernel versions will be used.
ifndef KERNEL_BUILD_DIR_PATH
	# KERNEL_VERSION var is to select any preinstalled kernel version from /lib/modules.
	# By default, the current kernel version will be used.
	ifndef KERNEL_VERSION
		KERNEL_VERSION = $(shell uname -r)
	endif
	KERNEL_BUILD_DIR = /lib/modules/$(KERNEL_VERSION)/build/
else
	KERNEL_BUILD_DIR = $(KERNEL_BUILD_DIR_PATH)
endif

.PHONY: all clean load unload

all:;   $(MAKE) -C $(KERNEL_BUILD_DIR) M=$(PWD) modules
clean:; $(MAKE) -C $(KERNEL_BUILD_DIR) M=$(PWD) clean
lint:; 	clang-tidy $(TARGET_MODULE).c
format:; clang-format -i $(TARGET_MODULE).c

load:;   sudo insmod $(TARGET_MODULE).ko
unload:; sudo rmmod  $(TARGET_MODULE).ko

