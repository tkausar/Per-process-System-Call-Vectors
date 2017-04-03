#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include "../regvec/syscall.h"
#include "ioctl_proc.h"

#define AUTHOR "Group 1"
#define DESCRIPTION "proc test"
#define DEVICE_NAME "ioctl_device"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);

extern unsigned long get_vector_address(char *vector_name);
extern char* get_vector_name(unsigned long addr);
extern int reduce_ref_count(char *vector_name);
struct mutex mut_lock;

static int add_to_task_structure(struct syscall_vector *sys_vec){
	int ret = -1;
	int pid;
	struct task_struct *tsk = NULL;

	tsk = get_current();
	pid = tsk->pid;
	if(tsk->syscall_data == NULL){
		ret = 0;
		printk(KERN_INFO "Adding vector address to void* syscall_data field");
		tsk->syscall_data = (void *)sys_vec;
	}
	return ret;
}

static void remove_from_task_struct(void){
	struct task_struct *tsk = NULL;
	tsk = get_current();
	if(tsk->syscall_data != NULL){
		printk(KERN_INFO "Removing vector address from void* syscall_data field");
		tsk->syscall_data = NULL;
	}
}


static long device_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param){
	int ret , pid;
	char *temp;
	char *vector_name;
	struct syscall_vector* sys_vec;
	struct task_struct *task = NULL;

	mutex_lock(&mut_lock);
	ret = 0;
	vector_name = NULL;
	sys_vec = NULL;
	temp = (char *)ioctl_param;
	vector_name = kmalloc(MAX_VECTOR_NAME_LEN, GFP_KERNEL);
	if(vector_name == NULL){
		ret = -ENOMEM;
		goto out;
	}
	if(IS_ERR(vector_name)){
		ret = PTR_ERR(vector_name);
		goto out;
	}
	switch(ioctl_num){
		case IOCTL_SET_VECTOR:
			try_module_get(THIS_MODULE);
			ret = copy_from_user(vector_name, temp, MAX_VECTOR_NAME_LEN);
			if(ret < 0){
				ret = -1;
				goto out;
			}
			printk(KERN_INFO " VECTOR_NAME_RECEIVED is: %s", vector_name);
			sys_vec = (struct syscall_vector *)get_vector_address(vector_name);
			if(sys_vec == NULL){
				ret = EINVAL;
			}
			else{
				ret = add_to_task_structure(sys_vec);
			}
			if(ret < 0){
				module_put(THIS_MODULE);
			}
			break;
		case IOCTL_REMOVE:
			ret = copy_from_user(vector_name, temp, MAX_VECTOR_NAME_LEN);
			if(ret < 0){
				ret = -1;
				goto out;
			}
			ret = reduce_ref_count(vector_name);
			if(ret < 0){
				ret = -EINVAL;
			}
			remove_from_task_struct();
			module_put(THIS_MODULE);
			break;
		default:
			ret = -1;
			break;
    case IOCTL_GET_VECTOR:
      ret = copy_from_user(vector_name, temp, MAX_VECTOR_NAME_LEN);
      if(ret < 0){
        ret = -1;
        goto out;
      }

      pid = simple_strtol(vector_name, NULL, 10);

      task = pid_task(find_vpid(pid), PIDTYPE_PID);
      if(task && task->syscall_data != NULL){ 
        vector_name = get_vector_name((unsigned long)task->syscall_data);
      }
      else {
        strcpy(vector_name, "default");
      }
     
      if (copy_to_user((char *)ioctl_param, (void *)vector_name, strlen(vector_name)))
      {
        printk ("%s: Input copy to user failed", __FUNCTION__);
      }
      
      printk(KERN_INFO "IOCTL_GET_VECTOR, vector_name= %s\n", vector_name);

      break;
    case IOCTL_SET_DEFAULT:
      ret = copy_from_user(vector_name, temp, MAX_VECTOR_NAME_LEN);
      if(ret < 0){
        ret = -1;
        goto out;
      }

      pid = simple_strtol(vector_name, NULL, 10);

      task = pid_task(find_vpid(pid), PIDTYPE_PID);
      if(task && task->syscall_data != NULL){
        vector_name = get_vector_name((unsigned long)task->syscall_data);
        ret = reduce_ref_count(vector_name);
        if(ret < 0){
          ret = -EINVAL;
        }
        
        task->syscall_data = NULL;
       
        module_put(THIS_MODULE);
        break;
      }

      printk(KERN_INFO "IOCTL_SET_DEFAULT\n");
      break;
	}
out :
	kfree(vector_name);
	mutex_unlock(&mut_lock);
	return (long)ret;
}

struct file_operations fops = {
.unlocked_ioctl = device_ioctl,
};

static int __init init_ioctl_module(void){
	int ret = 0;
	ret = register_chrdev(DEVICE_NUM, DEVICE_NAME, &fops);
	if(ret < 0){
		printk(KERN_ALERT "%s failed with %d\n",
				       "Sorry, registering the character device ", ret);
		goto out;
	}
	mutex_init(&mut_lock);
	out:
	return ret;
}

static void get_ioctl_module(void){
		 try_module_get(THIS_MODULE);
	}
EXPORT_SYMBOL(get_ioctl_module);

static void __exit exit_ioctl_module(void){
	unregister_chrdev(DEVICE_NUM, DEVICE_NAME);
}

module_init(init_ioctl_module);
module_exit(exit_ioctl_module);
