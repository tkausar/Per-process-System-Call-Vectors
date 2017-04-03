#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <asm/unistd_64.h>
#include <linux/moduleparam.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/err.h>
#include "../regvec/syscall.h"
#include "obscenity_filter.h"

#define MAX_BUF 512
#define AUTHOR "Group 1"
#define DESCRIPTION "obscenity_filter->replace offensive words"
#define RET_VAL -9999

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);


char vector_name[MAX_VECTOR_NAME_LEN] = "obscenity_filter";
struct syscall_vector *head_vector = NULL;

extern int register_syscall(char *vector_name, unsigned long vector_address, struct module *vector_module);
extern int unregister_syscall(unsigned long vector_address);

long obscenity_filter_open(const char __user *filename, int flags, umode_t mode){
	long ret = RET_VAL, i, err = 0;
	char *fname = NULL, *cur = NULL;

	fname = (char *)kmalloc(MAX_BUF, GFP_KERNEL);
	if(fname == NULL){
		ret = -ENOMEM;
		goto out;
	}

	if(IS_ERR(fname)){
		ret = PTR_ERR(fname);
		goto out;
	}

	err = copy_from_user(fname, filename, MAX_BUF);
	if(err < 0){
		ret = -EFAULT;
		goto out;
  }

  printk(KERN_INFO "In obscenity_filter Open, filename: %s, flags: %d, mode: %d\n", fname, flags, mode);
  
  // hide the obscene words
  if (flags & O_CREAT) {
    for(i = 0; i < obscene_buf_count; i++){
      cur = strstr(fname, obscene_buf[i]);
      if (cur) {
	      printk(KERN_INFO "Open: In obscenity_filter BLOCKING creation of file\n");
        ret = -EACCES;
      }
    }
  }


out :
  if(fname != NULL)
    kfree(fname);

  return ret;
}

long obscenity_filter_creat(const char __user *pathname, umode_t mode) {
  long ret = RET_VAL, i, err = 0;
  char *fname = NULL, *cur = NULL;

  fname = (char *)kmalloc(MAX_BUF, GFP_KERNEL);
  if(fname == NULL){
    ret = -ENOMEM;
    goto out;
  }

  if(IS_ERR(fname)){
    ret = PTR_ERR(fname);
    goto out;
  }

  err = copy_from_user(fname, pathname, MAX_BUF);
  if(err < 0){
    ret = -EFAULT;
    goto out;
  }

  printk(KERN_INFO "In obscenity_filter Create, filename: %s, mode: %d\n", fname, mode);
  
  // hide the obscene words
  for(i = 0; i < obscene_buf_count; i++){
    cur = strstr(fname, obscene_buf[i]);
    if (cur) {
      printk(KERN_INFO "Creat: In obscenity_filter BLOCKING creation of file\n");
      ret = -EACCES;
    }
  }


out :
  if(fname != NULL)
    kfree(fname);

  return ret;
}

long obscenity_filter_read(unsigned int fd, char __user *buf, size_t count){
	int ret = 0, err = 0, i,j;
  char *out_buf = NULL, *cur = NULL;

  if (fd == 0 || fd == 1 || fd == 2)
    goto out;

	out_buf = (char *)kmalloc(MAX_BUF, GFP_KERNEL);
	if(out_buf == NULL){
		ret = -ENOMEM;
		goto out;
	}

	if(IS_ERR(out_buf)){
		ret = PTR_ERR(out_buf);
		goto out;
	}

  err = copy_from_user(out_buf, buf, count);
  if(err)
  {
     printk ("Input copy from user failed, err = %d\n", err);
     ret = -EINVAL;
     goto out;
   }

   //printk(KERN_INFO "before change read buffer---> %s", out_buf);

   // hide the obscene words
   for(i = 0; i < obscene_buf_count; i++){
     cur = strstr(out_buf, obscene_buf[i]);
     if (cur) {
       for (j=1;j<strlen(obscene_buf[i]);j++)
         cur[j] = '*';
     }
   }

   //printk(KERN_INFO "after change read buffer---> %s", out_buf);

  ret = copy_to_user(buf, out_buf, count);
	if(ret < 0){
		ret = -EFAULT;
		goto out;
	}

	printk(KERN_INFO "In obscenity_filter read, fd: %u, count: %lu\n", fd, count);
	
  out:
	if(out_buf != NULL){
		kfree(out_buf);
	}

	return ret;
}

long obscenity_filter_write(unsigned int fd, char __user *buf, size_t count){
  int ret = RET_VAL, err = 0, i,j;
  char *out_buf = NULL, *cur = NULL;

  if (fd == 0 || fd == 1 || fd == 2)
    goto out;

  
  out_buf = (char *)kmalloc(MAX_BUF, GFP_KERNEL);
  if(out_buf == NULL){
    ret = -ENOMEM;
    goto out;
  }

  if(IS_ERR(out_buf)){
    ret = PTR_ERR(out_buf);
    goto out;
  }

  err = copy_from_user(out_buf, buf, count);
  if(err)
  {
    printk ("Input copy from user failed, err = %d\n", err);
    ret = -EINVAL;
    goto out;
  }

//  printk(KERN_INFO "before write buffer---> %s", out_buf);

  for(i = 0; i < obscene_buf_count; i++){
    cur = strstr(out_buf, obscene_buf[i]);
    if (cur) {
      for (j=1;j<strlen(obscene_buf[i]);j++)
        cur[j] = '*';
    }
  }

//  printk(KERN_INFO "after write buffer---> %s", out_buf);

  ret = copy_to_user(buf, out_buf, count);
  if(ret < 0){
    ret = -EFAULT;
    goto out;
  }
 
  ret = RET_VAL;

	printk(KERN_INFO "In obscenity_filter write, fd: %u, count: %lu\n", fd, count);

out:
  if(out_buf != NULL){
    kfree(out_buf);
  }
  return ret;
}

long obscenity_filter_close(unsigned int fd)
{
  long ret = RET_VAL;

	printk(KERN_INFO "In obscenity_filter close, fd:%d\n", fd);

  return ret;
}

long obscenity_filter_fchown(unsigned int fd, uid_t user, gid_t group){
  int i;

  printk(KERN_INFO "In obscenity_filter fchown, fd: %u, userid: %u, groupid: %u\n", fd, (unsigned int)user, (unsigned int)group);

  for(i = 0; i < blocked_userId_count; i++){
    if (blocked_userId[i] == user) {
	    printk(KERN_INFO "In obscenity_filter, BLOCKING fchown\n");
      return -EACCES;
    }
  }

  return RET_VAL;
}

static int add_syscall_to_vector(int syscall_no, unsigned long func_ptr){
	int ret = 0;
	struct syscall_vector *sys_vector = NULL;
	struct syscall_vector *temp = NULL;

	sys_vector = (struct syscall_vector *)kmalloc(sizeof(struct syscall_vector), GFP_KERNEL);
	if(sys_vector == NULL){
		ret = -ENOMEM;
		goto out;
	}

	if(IS_ERR(sys_vector)){
		ret = PTR_ERR(sys_vector);
		goto out;
	}

	memset(sys_vector, 0, sizeof(struct syscall_vector));
	
  sys_vector->sys_call.syscall_no = syscall_no;
	sys_vector->sys_call.function_ptr = func_ptr;

	if(head_vector == NULL){
		head_vector = sys_vector;
		goto out;
	}
	
  temp = head_vector;
	while(temp->next != NULL){
		temp = temp->next;
	}
	temp->next = sys_vector;
	out:
	return ret;
}

static int initialize_syscall_vector(void){
	int ret = 0;

	ret = add_syscall_to_vector(__NR_open, (unsigned long)obscenity_filter_open);
	if(ret < 0){
		goto out;
	}
	ret = add_syscall_to_vector(__NR_creat, (unsigned long)obscenity_filter_creat);
	if(ret < 0){
		goto out;
	}
	ret = add_syscall_to_vector(__NR_read, (unsigned long)obscenity_filter_read);
	if(ret < 0){
		goto out;
  }
  ret = add_syscall_to_vector(__NR_write, (unsigned long)obscenity_filter_write);
  if(ret < 0){
    goto out;
  }
	ret = add_syscall_to_vector(__NR_fchown, (unsigned long)obscenity_filter_fchown);
	if(ret < 0){
		goto out;
	}
  ret = add_syscall_to_vector(__NR_close, (unsigned long)obscenity_filter_close);
  if(ret < 0){
    goto out;
  }
  ret = register_syscall(vector_name, (unsigned long)head_vector, THIS_MODULE);
out:
	return ret;
}

static void delete_vector(void){
	struct syscall_vector *temp = NULL;
	struct syscall_vector *new = NULL;
	new = head_vector;

	if(head_vector == NULL){
		goto end;
	}
	while(new->next != NULL){
		temp = new;
		new = new->next;
		kfree(temp);
		temp = NULL;
	}
	kfree(new);
	new = NULL;
	head_vector = NULL;
	goto end;
end:
;
}

static int __init init_override(void){
	int ret = 0;
	ret = initialize_syscall_vector();
	if(ret < 0){
		delete_vector();
	}
	return ret;
}


static void __exit cleanup_override(void){
	int ret;
	ret = unregister_syscall((unsigned long)head_vector);
	if(head_vector != NULL){
		delete_vector();
	}
}

module_init(init_override);
module_exit(cleanup_override);
