# obj-m is a list of what kernel modules to build.  The .o and other
# objects will be automatically built from the corresponding .c file -
# no need to list the source files explicitly.

obj-m := uio_ivshmem.o shadow.o vuart.o shadow-v11.o exec.o ivshmem-net.o uio_ivshmem-v11.o ivshmem-net-v11.o exit.o

# KDIR is the location of the kernel source.  The current standard is
# to link to the associated source tree from the directory containing
# the compiled modules.
KDIR  := /lib/modules/$(shell uname -r)/build

# PWD is the current working directory and the location of our module
# source files.
PWD   := $(shell pwd)

# default is the default make target.  The rule here says to run make
# with a working directory of the directory containing the kernel
# source and compile only the modules in the PWD (local) directory.
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	cp uio_ivshmem.ko /lib/modules/$(shell uname -r)/kernel/drivers/uio/
	cp shadow.ko /lib/modules/$(shell uname -r)/kernel/drivers/uio/
	cp shadow-v11.ko /lib/modules/$(shell uname -r)/kernel/drivers/uio/
	cp vuart.ko /lib/modules/$(shell uname -r)/kernel/drivers/uio/
	cp exec.ko /lib/modules/$(shell uname -r)/kernel/drivers/uio/

clean:
	rm -f *.ko *.o uio_ivshmem.mod.c Module.symvers
	rm -f *.ko *.o shadow.mod.c Module.symvers
	rm -f *.ko *.o shadow-v11.mod.c Module.symvers
	rm -f *.ko *.o vuart.mod.c Module.symvers
