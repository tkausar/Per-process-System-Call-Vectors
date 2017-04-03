obj-y := syscall_check.o

all: build

build:
	make -C /lib/modules/$(shell uname -r)/build -I/usr/src/hw3-cse506g12/include M=$(PWD) 