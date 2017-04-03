#include <linux/slab.h>
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include "../regvec/syscall.h"

extern void get_ioctl_module(void);
extern unsigned long get_vector_address(char *vector_name);
asmlinkage extern long (*sysptr)(unsigned long);
asmlinkage long sys_clone2(unsigned long vec_name)
{	
	char *temp;
	char *vector_name;
	int ret = 0;
	struct syscall_vector* sys_vec = NULL;
	temp = (char *)vec_name;
	vector_name = kmalloc(MAX_VECTOR_NAME_LEN, GFP_KERNEL);
	if(vector_name == NULL){
		ret = -ENOMEM;
		goto out;
	}
	if(IS_ERR(vector_name)){
		ret = PTR_ERR(vector_name);
		goto out;
	}
	ret = copy_from_user(vector_name, temp, MAX_VECTOR_NAME_LEN);
	if(ret < 0){
		ret = -1;
		goto out;
	}
	get_ioctl_module();
	sys_vec = (struct syscall_vector *)get_vector_address(vector_name);
	if(sys_vec == NULL){
		ret = -EINVAL;
	}
	printk(KERN_INFO "vector name received %s\n", vector_name);
	printk("clone2 system call called\n");	
out:
	if(vector_name)
		kfree(vector_name);
	return _do_fork(SIGCHLD, 0, 0, NULL, NULL, 0, (void *)sys_vec);
}

static int __init init_sys_clone2(void){
	
printk(KERN_INFO "installed new sys_clone2 module\n");
	if(sysptr == NULL){
		sysptr = sys_clone2;
	}
	return 0;
}

static void __exit exit_sys_clone2(void){
	if(sysptr != NULL)
		sysptr = NULL;
	printk(KERN_INFO "removed sys_clone2 module\n");
}

module_init(init_sys_clone2);
module_exit(exit_sys_clone2);
MODULE_LICENSE("GPL");
