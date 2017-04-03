KBUILD_EXTRA_SYMBOLS := /usr/src/hw3-cse506p01/hw3/regvec/Module.symvers
obj-m += ioctl_vector.o

all:  module

module:
	make -C /lib/modules/$(shell uname -r)/build -I/usr/src/hw3-cse506g12/include M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
