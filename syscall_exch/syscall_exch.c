#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/module.h>
#include<linux/syscalls.h>
#include<linux/kobject.h>
#include<linux/slab.h>
#include<linux/cred.h>
#include<linux/namei.h>
#include<linux/path.h>
#include<linux/file.h>
#include<linux/fs.h>
#include<linux/string.h>
#include "../regvec/reg_sys_vec.h"
#include "../regvec/syscall.h"

MODULE_LICENSE("GPL");

#define START_SYSCALL 0xffffffff81000000
#define END_SYSCALL   0xffffffffa2000000

unsigned long *system_call_table_array;

/*function declarations.*/
int syscall_exch_init(void);
void syscall_exch_exit(void);
unsigned long **find_syscall_table(void);
void disable_write_protection(void);
void enable_write_protection(void);


/*original system calls to be hacked.*/
ssize_t (*write_syscall)(int fd, const char __user *buf, ssize_t count);
int (*close_syscall)(unsigned int fd);
ssize_t (*read_syscall)(int fd, void *buf, size_t count);
ssize_t (*open_syscall)(const char __user *filename,int flags, umode_t mode);
ssize_t (*creat_syscall)(const char __user *filename, umode_t mode);
int (*fchown_syscall)(int fd, uid_t owner, gid_t group);
long (*link_syscall)(const char __user *oldname, const char __user *newname);
long (*unlink_syscall)(const char __user *pathname);
long (*mkdir_syscall)(const char __user *pathname,umode_t mode);
long (*rmdir_syscall)(const char __user *pathname);
long (*chmod_syscall)(const char __user *filename,umode_t mode);

/*syscall_exch version of hijacked system calls.*/
ssize_t syscall_exch_write(int fd, const char __user *buf, ssize_t count);
long syscall_exch_close(unsigned int fd);
ssize_t syscall_exch_read(int fd, void *buf, size_t count);
long syscall_exch_link(const char __user *oldname, const char __user *newname);
long syscall_exch_unlink(const char __user *pathname);
long syscall_exch_mkdir(const char __user *pathname,umode_t mode);


/*function to find the system call table starting address in memory.*/
unsigned long **find_syscall_table(void){
  unsigned long **system_call_table_array;
  unsigned long i = START_SYSCALL;
  while(i < END_SYSCALL){
    system_call_table_array = (unsigned long **)i;
    if(system_call_table_array[__NR_close] == (unsigned long *) sys_close)
      return &system_call_table_array[0];
    i = i + sizeof(void *);
  }
  return NULL;
}

/*function to disable control register write protection.*/
void disable_write_protection(void){
  unsigned long cr0, bit_16;
  bit_16 = 0x10000;
  cr0 = read_cr0() & (~bit_16);
  write_cr0(cr0);
}
/*function to enable control register write protection.*/
void enable_write_protection(void){
  unsigned long cr0, bit_16;
  bit_16 = 0x10000;
  cr0 = read_cr0() | bit_16;
  write_cr0(cr0);
}

unsigned long get_vector_address(int syscall_number)
{
  struct syscall_vector* vector_head = NULL;
  struct syscall_vector* temp = NULL;
  struct task_struct *curr = get_current();
  if(curr->syscall_data != NULL){
    vector_head = (struct syscall_vector*)curr->syscall_data;
    temp = vector_head;
    while(temp != NULL){
      if(temp->sys_call.syscall_no == syscall_number){
        return temp->sys_call.function_ptr;
      }
      temp = temp->next;
    }
  }
  return 0;
}

long syscall_exch_close(unsigned int fd){
  long ret = 0;
  long (*fun_ptr)(unsigned int);
  unsigned long func_addr;

  func_addr = get_vector_address(__NR_close);
  if (func_addr)
  {
    fun_ptr = (void*) func_addr;
    ret = fun_ptr(fd);
  }

  ret = (close_syscall)(fd);
  return ret;
}

ssize_t syscall_exch_write(int fd, const char __user *buf, ssize_t count){
  long ret = 0;
  long (*fun_ptr)(unsigned int, char __user*,size_t);
  unsigned long func_addr;

  if (fd == 0 || fd == 1 || fd == 2)
    goto out;

  func_addr = get_vector_address(__NR_write);
  if (func_addr)
  {
    fun_ptr = (void*) func_addr;
    ret = fun_ptr(fd,(char __user *)buf,count);
  }

out:
  ret = (write_syscall)(fd, buf, count);
  return ret;
}

int syscall_exch_fchown(int fd, uid_t owner, gid_t group)
{
  int ret = 0;
  unsigned long func_addr;
  long (*fun_ptr)(int, uid_t, gid_t);
  
  func_addr = get_vector_address(__NR_fchown);
  if (func_addr)
  {
    fun_ptr = (void*) func_addr;
    ret = fun_ptr(fd,owner,group);
  }

  if (ret >=0)
    ret = (*fchown_syscall)(fd,owner,group);

  return ret;
}

long syscall_exch_open(const char __user *filename,int flags, umode_t mode)
{
  long ret = 0;
  unsigned long func_addr;
  long (*fun_ptr)(const char __user*,int, umode_t);

  func_addr = get_vector_address(__NR_open);
  if (func_addr)
  {
    fun_ptr = (void*) func_addr;
    ret = fun_ptr(filename, flags, mode);
  }

  if (ret >= 0)
    ret = (open_syscall)(filename, flags, mode);
  
  return ret;
}

long syscall_exch_creat(const char __user *filename, umode_t mode)
{
  long ret = 0;
  unsigned long func_addr;
  long (*fun_ptr)(const char __user*, umode_t);

  func_addr = get_vector_address(__NR_creat);
  if (func_addr)
  {
    fun_ptr = (void*) func_addr;
    ret = fun_ptr(filename, mode);
  }

  if (ret >= 0)
    ret = (creat_syscall)(filename, mode);

  return ret;
}


ssize_t syscall_exch_read(int fd, void *buf, size_t count){

  ssize_t ret = 0, ret2 = 0;
  long (*fun_ptr)(unsigned int, char __user*,size_t);
  unsigned long func_addr;
  
	ret = (read_syscall)(fd, buf, count);
  
  if (fd == 0 || fd == 1 || fd == 2)
    goto out;
  
  func_addr = get_vector_address(__NR_read);
  if (func_addr)
  {
    fun_ptr = (void*) func_addr;
    ret2 = fun_ptr(fd,buf,count);
  }

out:
	return ret;
}

long syscall_exch_link(const char __user *oldname, const char __user *newname){
  long ret = 0;
  long (*fun_ptr)(const char __user*, const char __user*);
  unsigned long func_addr;

  func_addr = get_vector_address(__NR_link);
  if (func_addr)
  {
    fun_ptr = (void*) func_addr;
     ret = fun_ptr(oldname,newname);
  }
  if(ret==1000)
  {
    printk("Operation Disabled : You are not allowed to link this file\n");
  }
  else
    ret = (link_syscall)(oldname,newname);
  return ret;
}

long syscall_exch_unlink(const char __user *pathname){
  long ret = 0;
  long (*fun_ptr)(const char __user*);
  unsigned long func_addr;

  func_addr = get_vector_address(__NR_unlink);
  if (func_addr)
  {
    fun_ptr = (void*) func_addr;
    ret = fun_ptr(pathname);
  }
  if(ret==1000)
  {
    printk("Operation Disabled : You are not allowed to unlink this file\n");
  }
  else
    ret = (unlink_syscall)(pathname);
  return ret;
}

long syscall_exch_mkdir(const char __user *pathname, umode_t mode){
  long ret = 0;
  long (*fun_ptr)(const char __user*,umode_t);
  unsigned long func_addr;

  func_addr = get_vector_address(__NR_mkdir);    //if syscall is found in registered vector, it returns the vector's func_addr for mkdir
  if (func_addr)
  {
    fun_ptr = (void*) func_addr;
    ret = fun_ptr(pathname,mode);
  }
  if(ret==1000)                                 //return value 1000 refers to disabled syscall
  {
    printk("Operation Disabled : You are not allowed to create directory\n");
  }
  else
    ret = (mkdir_syscall)(pathname,mode);
  return ret;
}

long syscall_exch_rmdir(const char __user *pathname){
  long ret = 0;
  long (*fun_ptr)(const char __user*);
  unsigned long func_addr;

  func_addr = get_vector_address(__NR_rmdir);    //if syscall is found in registered vector, it returns the vector's func_addr 
  if (func_addr)
  {
    fun_ptr = (void*) func_addr;
    ret = fun_ptr(pathname);
  }
  if(ret==1000)                                 //return value 1000 refers to disabled syscall
  {
    printk("Operation Disabled : You are not allowed to remove directory\n");
  }
  else
    ret = (rmdir_syscall)(pathname);
  return ret;
}

long syscall_exch_chmod(const char __user *filename, umode_t mode){
  long ret = 0;
  long (*fun_ptr)(const char __user*,umode_t);
  unsigned long func_addr;

  func_addr = get_vector_address(__NR_chmod);    //if syscall is found in registered vector, it returns the vector's func_addr 
  if (func_addr)
  {
    fun_ptr = (void*) func_addr;
    ret = fun_ptr(filename,mode);
  }
  if(ret==1000)                                 //return value 1000 refers to disabled syscall
  {
    printk("Operation Disabled : You are not allowed to change permission\n");
  }
  else
    ret = (chmod_syscall)(filename,mode);
  return ret;
}


int syscall_exch_init(void){

  //unsigned long *system_call_table_array = NULL;
  if((system_call_table_array = (unsigned long *)find_syscall_table())){
    printk("syscall_exch:syscall table found\n");
  }
  else{
    printk("syscall_exch:syscall table not found\n");

  }

  disable_write_protection();
  write_syscall = (void *)xchg(&system_call_table_array[__NR_write], (unsigned long)syscall_exch_write);
  close_syscall = (void *)xchg(&system_call_table_array[__NR_close], (unsigned long)syscall_exch_close);
  read_syscall = (void *)xchg(&system_call_table_array[__NR_read], (unsigned long)syscall_exch_read);
  open_syscall = (void *)xchg(&system_call_table_array[__NR_open], (unsigned long)syscall_exch_open);
  creat_syscall = (void *)xchg(&system_call_table_array[__NR_creat], (unsigned long)syscall_exch_creat);
  fchown_syscall = (void *)xchg(&system_call_table_array[__NR_fchown], (unsigned long)syscall_exch_fchown);
  link_syscall = (void *)xchg(&system_call_table_array[__NR_link], (unsigned long)syscall_exch_link);
  unlink_syscall = (void *)xchg(&system_call_table_array[__NR_unlink], (unsigned long)syscall_exch_unlink);
  mkdir_syscall = (void *)xchg(&system_call_table_array[__NR_mkdir], (unsigned long)syscall_exch_mkdir);
  rmdir_syscall = (void *)xchg(&system_call_table_array[__NR_rmdir], (unsigned long)syscall_exch_rmdir);
  chmod_syscall = (void *)xchg(&system_call_table_array[__NR_chmod], (unsigned long)syscall_exch_chmod);
  enable_write_protection();
 
  printk("syscall_exch:initialized\n");
  return 0;
}

void syscall_exch_exit(void){
  disable_write_protection();
  system_call_table_array[__NR_close] = (unsigned long)close_syscall;
  system_call_table_array[__NR_open] = (unsigned long)open_syscall;
  system_call_table_array[__NR_creat] = (unsigned long)creat_syscall;
  system_call_table_array[__NR_read] = (unsigned long)read_syscall;
  system_call_table_array[__NR_fchown] = (unsigned long)fchown_syscall;
  system_call_table_array[__NR_write] = (unsigned long)write_syscall;
  system_call_table_array[__NR_link] = (unsigned long)link_syscall;
  system_call_table_array[__NR_unlink] = (unsigned long)unlink_syscall;
  system_call_table_array[__NR_mkdir] = (unsigned long)mkdir_syscall;
  system_call_table_array[__NR_rmdir] = (unsigned long)rmdir_syscall;
  system_call_table_array[__NR_chmod] = (unsigned long)chmod_syscall;
  enable_write_protection();
  printk("syscall_exch:exit\n");
}

module_init(syscall_exch_init);
module_exit(syscall_exch_exit);
