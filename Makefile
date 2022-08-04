# modules
obj-m := aquadev.o
RPI-KENL = /usr/src/rpi-kernel
MOUDULE_FLAGS = -C $(RPI-KENL)  M=$(PWD) ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf-

# files
CC=arm-linux-gnueabihf-gcc
CFLAGS=-o ./files -g -I./inc

.PHONY: files copy load unload module

module:
	make $(MOUDULE_FLAGS) modules
clean:
	make $(MOUDULE_FLAGS) clean
copy: module
	scp ./aquadev.ko aqua@aqua-rpi:/tmp/
load: copy
	ssh aqua@aqua-rpi.local "sudo /usr/sbin/insmod /tmp/aquadev.ko"
unload:
	ssh aqua@aqua-rpi.local "sudo /usr/sbin/rmmod /tmp/aquadev.ko"
files:
	$(CC) $(CFLAGS) files.c utils.c cparser_tree.c cmd.c ./lib/libcparser.a
