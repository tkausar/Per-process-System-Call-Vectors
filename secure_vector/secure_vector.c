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

#define MAX_BUF 512
#define AUTHOR "Group 1"
#define DESCRIPTION "secure_vector->disabled-mkdir-rmdir-link-unlink-rename"
#define SECURE_KEYWORD "protect"
#define RET_VAL -9999

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);

char vector_name[MAX_VECTOR_NAME_LEN] = "secure_vector";
struct syscall_vector *head_vector = NULL;

extern int register_syscall(char *vector_name, unsigned long vector_address, struct module *vector_module);
extern int unregister_syscall(unsigned long vector_address);

long secure_vector_link_syscall( const char __user *oldname, const char __user *newname ){
  int ret = RET_VAL;         
  char *fname = NULL;

  fname = (char *)kmalloc(MAX_BUF, GFP_KERNEL);
  if (fname == NULL) {
    ret = -ENOMEM;
    goto out;
  }
  if (IS_ERR(fname)) {
    ret = PTR_ERR(fname);
    goto out;
  }

  ret = copy_from_user(fname, oldname, MAX_BUF);
  if(ret < 0) {                                
    ret = -EFAULT;
    goto out;
  } 

  printk(KERN_INFO "link oldname: %s\n", fname );
  if(strstr(fname,SECURE_KEYWORD)!=NULL) 
  {
    printk(KERN_INFO "link oldname: %s contains protect keyword\n", fname );
    ret = 1000;
    goto out;
  }


  memset(fname, 0, MAX_BUF);

  ret = copy_from_user(fname, newname, MAX_BUF);
  if(ret < 0) {                                
    ret = -EFAULT;
    goto out;
  } 
  printk(KERN_INFO "link newname: %s\n", fname );
 
 ret = RET_VAL;

out:
  if(fname != NULL)
    kfree(fname);
  return ret;
}

long secure_vector_unlink_syscall( const char __user *pathname ){
  int ret = RET_VAL;
  char *fname = NULL;

  fname = (char *)kmalloc(MAX_BUF, GFP_KERNEL);
  if (fname == NULL) {
    ret = -ENOMEM;
    goto out;
  }
  if (IS_ERR(fname)) {
    ret = PTR_ERR(fname);
    goto out;
  }

  ret = copy_from_user(fname, pathname, MAX_BUF);
  if(ret < 0) {
    ret = -EFAULT;
    goto out;
  }

  printk(KERN_INFO "unlink pathname: %s\n", fname );
  if(strstr(fname,SECURE_KEYWORD)!=NULL) //change
  {
    printk(KERN_INFO "unlink pathname: %s contains protect keyword\n", fname );
    ret = 1000;
    goto out;
  }
 
 ret = RET_VAL;

out:
  if(fname != NULL)
    kfree(fname);
  return ret;
}

long secure_vector_mkdir_syscall( const char __user *pathname,umode_t mode  ){
  int ret = RET_VAL;
  char *fname = NULL;

  fname = (char *)kmalloc(MAX_BUF, GFP_KERNEL);
  if (fname == NULL) {
    ret = -ENOMEM;
    goto out;
  }
  if (IS_ERR(fname)) {
    ret = PTR_ERR(fname);
    goto out;
  }

  ret = copy_from_user(fname, pathname, MAX_BUF);
  if(ret < 0) {
    ret = -EFAULT;
    goto out;
  }

  printk(KERN_INFO "mkdir pathname: %s\n", fname );
  if(strstr(fname,SECURE_KEYWORD)!=NULL) //change
  {
  printk(KERN_INFO "mkdir pathname: %s contains protect\n", fname );
  ret = 1000;
  goto out;
  }
 ret = RET_VAL;
out:
  if(fname != NULL)
    kfree(fname);
  return ret;
}

long secure_vector_rmdir_syscall( const char __user *pathname){
  int ret = RET_VAL;
  char *fname = NULL;

  fname = (char *)kmalloc(MAX_BUF, GFP_KERNEL);
  if (fname == NULL) {
    ret = -ENOMEM;
    goto out;
  }
  if (IS_ERR(fname)) {
    ret = PTR_ERR(fname);
    goto out;
  }

  ret = copy_from_user(fname, pathname, MAX_BUF);
  if(ret < 0) {
    ret = -EFAULT;
    goto out;
  }

  printk(KERN_INFO "rmdir pathname: %s\n", fname );
  if(strstr(fname,SECURE_KEYWORD)!=NULL)
  {
    printk(KERN_INFO "rmdir pathname: %s contains protect keyword\n", fname );
    ret = 1000;
    goto out;
  }

 ret = RET_VAL;
out:
  if(fname != NULL)
    kfree(fname);
  return ret;
}

long secure_vector_chmod_syscall( const char __user *filename,umode_t mode  ){
  int ret = RET_VAL;
  char *fname = NULL;

  fname = (char *)kmalloc(MAX_BUF, GFP_KERNEL);
  if (fname == NULL) {
    ret = -ENOMEM;
    goto out;
  }
  if (IS_ERR(fname)) {
    ret = PTR_ERR(fname);
    goto out;
  }

  ret = copy_from_user(fname, filename, MAX_BUF);
  if(ret < 0) {
    ret = -EFAULT;
    goto out;
  }

  printk(KERN_INFO "chmod filename: %s\n", fname );
  if(strstr(fname,SECURE_KEYWORD)!=NULL) //change
  {
    printk(KERN_INFO "chmod filename: %s contains protect\n", fname );
    ret = 1000;
    goto out;
  }
 ret = RET_VAL;
out:
  if(fname != NULL)
    kfree(fname);
  return ret;
}

//---------------------syscalls decalaration end----------------------//

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
  ret = add_syscall_to_vector(__NR_link, (unsigned long)secure_vector_link_syscall);
  if(ret < 0){
    goto out;
  }
  ret = add_syscall_to_vector(__NR_unlink, (unsigned long)secure_vector_unlink_syscall);
  if(ret < 0){
    goto out;
  }
  ret = add_syscall_to_vector(__NR_mkdir, (unsigned long)secure_vector_mkdir_syscall);
  if(ret < 0){
    goto out;
  }
  ret = add_syscall_to_vector(__NR_rmdir, (unsigned long)secure_vector_rmdir_syscall);
  if(ret < 0){
    goto out;
  }
 ret = add_syscall_to_vector(__NR_chmod, (unsigned long)secure_vector_chmod_syscall);
   if(ret < 0){
       goto out;
         }


  printk("Added syscalls to secure_vector. Now registering the vector!!\n");
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

static int __init init_securevectors(void){
  int ret = 0;
  ret = initialize_syscall_vector();
  if(ret < 0){
    delete_vector();
  }
  return ret;
}

static void __exit exit_securevectors(void){
  int ret;
  ret = unregister_syscall((unsigned long)head_vector);
  if(head_vector != NULL){
    delete_vector();
  }
}

module_init(init_securevectors);
module_exit(exit_securevectors);

