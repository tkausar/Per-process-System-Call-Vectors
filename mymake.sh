rmmod obscenity_filter
rmmod secure_vector
rmmod sys_clone2
rmmod ioctl_vector
rmmod reg_sys_vec
#rmmod syscall_exch
cd regvec
make
insmod reg_sys_vec.ko
#cd ../syscall_exch
#make
#insmod syscall_exch.ko
#cd ../syscall_check/
#make
cd ../obscenity_filter/
make
insmod obscenity_filter.ko
cd ../secure_vector/
make
insmod secure_vector.ko
cd ../vec_ioctl/
mknod /dev/ioctl_device c 121 212
make
insmod ioctl_vector.ko
cd ../syscall_clone
make
insmod sys_clone2.ko

