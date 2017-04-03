#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include<linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>


#include "reg_sys_vec.h"

#define EXPORT_SYMTAB
#define AUTHOR "GROUP-1"
#define DESCRIPTION "register and unregister syscalls"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);

static const char filename[] = "syscall_vectors";
struct proc_dir_entry* pde = NULL;

struct new_vector *head = NULL;
char buffer[MAX_BUFFER_SIZE];
struct mutex list_lock;


static ssize_t show_vectors(struct file *file, char *user_buffer, size_t buffer_length, loff_t *offset){
    int ret;
    char *current_ptr;
    struct new_vector *temp;
    int vec_len,head_len=0,index;
    ret = 0;
    temp = NULL;
    current_ptr = NULL;
    if(*offset > 0){     
        ret = 0;
        goto out;
    }
    memset(buffer, 0, MAX_BUFFER_SIZE);   //buffer is set
    current_ptr = buffer;                 //pointing current_ptr to buffer
    if(head == NULL){                     //head is the root of syscall vector linked list
        goto out;
    }
    strcpy(current_ptr,"Vector Name        Number of Processes\n");
    head_len = strlen(current_ptr);
    current_ptr += head_len;
    ret = ret + head_len;
    temp = head;
    while((temp != NULL) && (ret < MAX_BUFFER_SIZE)){     //traversing through the vector's linked list
        vec_len = strlen(temp->vector_name);
        memcpy(current_ptr, temp->vector_name, vec_len);  //copying vector_name 
        current_ptr += vec_len;
        index = strlen(current_ptr);
        current_ptr[index]= '\t';
        current_ptr[index+1]= temp->ref_count + '0';      //adding reference count   
        current_ptr[index+2] = '\n';          
        current_ptr = current_ptr + 3;
        ret = ret + vec_len + 3;
        temp = temp->next;
        
    }
    memcpy(user_buffer, buffer, ret);
    out:
    *offset=ret;   //updating offset explicitly
    return ret;
}

static int add_vector_address(char *vector_name, unsigned long vector_address, struct module *vector_module){
    int ret = 0;
    struct new_vector *va = NULL;
    struct new_vector *temp = NULL;
    va = (struct new_vector*)kmalloc(sizeof(struct new_vector), GFP_KERNEL);
    if(va == NULL){
        ret = -ENOMEM;
        goto out;
    }
    if(IS_ERR(va)){
        ret = PTR_ERR(va);
        goto out;
    }

    memset(va, 0, sizeof(struct new_vector));

    memcpy(va->vector_name, vector_name, strlen(vector_name));
    va->vector_address = vector_address;
    va->ref_count = 0;
    va->vector_module = vector_module;
    va->next = NULL;

    if(head == NULL){
        head = va;
        goto out;
    }

    temp = head;
    while (temp->next != NULL){
        temp = temp->next;
    }

    temp->next = va;
    out:
    return ret;
}


static int remove_vector_address(unsigned long vector_address){
    int ret = 0;
    int flag = 0;
    struct new_vector *ptr = NULL;
    struct new_vector *temp = NULL;

    if(head == NULL){
        ret = -EFAULT;
        goto out;
    }

    if((head->next == NULL) && (head->vector_address == vector_address)){
        ptr = head;
        goto check_ref_count;
    }
    else if(head->next != NULL){
        temp = head;
        ptr = temp->next;
        while (ptr != NULL){
            if(ptr->vector_address == vector_address){
                flag = 1;
                break;
            }
            ptr = ptr->next;
            temp = ptr;
        }
    }
    else;

    if(flag == 0){
        ret = -EFAULT;
        goto out;
    }

    check_ref_count:
        if(ptr->ref_count > 0){
            ret = -2222;
            goto out;
        }
        if(ptr != head)
            temp->next = ptr->next;
        else
            head = NULL;
        kfree(ptr);
        ptr = NULL;
    out:
    return ret;
}

int register_syscall(char *vector_name, unsigned long vector_address, struct module* vector_module){
    int ret = 0;
    mutex_lock(&list_lock);
    ret = add_vector_address(vector_name, vector_address, vector_module);
    mutex_unlock(&list_lock);
    if(ret < 0){
        goto out;
    }
    out:
    return ret;
}
EXPORT_SYMBOL(register_syscall);

int unregister_syscall(unsigned long vector_address){
    int ret = 0;

    mutex_lock(&list_lock);
    ret = remove_vector_address(vector_address);
    mutex_unlock(&list_lock);
    if(ret < 0){
        goto out;
    }
    out:
    return ret;
}

EXPORT_SYMBOL(unregister_syscall);


unsigned long get_vector_address(char *vector_name){
    unsigned long va = 0;
    struct new_vector *temp = NULL;
    mutex_lock(&list_lock);
    if(head == NULL){
        mutex_unlock(&list_lock);
        goto out;
    }
    temp = head;
    while (temp != NULL){
        if(memcmp(temp->vector_name, vector_name, strlen(vector_name)) == 0){
            if(strlen(vector_name) == strlen(temp->vector_name))
                break;
        }
        temp = temp->next;
    }

    if(temp != NULL){
        temp->ref_count = temp->ref_count +1;
        try_module_get(temp->vector_module);
        va = temp->vector_address;
    }
    mutex_unlock(&list_lock);
    out:
    return va;
}
EXPORT_SYMBOL(get_vector_address);

#define MAX_NAME 100

char* get_vector_name(unsigned long addr){
  char *vector_name = NULL;
  struct new_vector *temp = NULL;
  
  vector_name = kmalloc(MAX_NAME,GFP_KERNEL);
  if (vector_name == NULL) {
    goto out;
  }

  mutex_lock(&list_lock);
  if(head == NULL){
    mutex_unlock(&list_lock);
    goto out;
  }
  temp = head;
  while (temp != NULL){
    if(temp->vector_address == addr){
        strcpy (vector_name, temp->vector_name);
        break;
    }
    temp = temp->next;
  }

  mutex_unlock(&list_lock);

  //printk("get_vector_name, vector name- %s", vector_name);
out:
  return vector_name;
}
EXPORT_SYMBOL(get_vector_name);

int reduce_ref_count(char *vector_name){
    int ref_cnt = -1;
    struct new_vector *temp = NULL;

    mutex_lock(&list_lock);
    if(head == NULL){
        goto out;
    }
    temp = head;
    while (temp != NULL){
        if(memcmp(temp->vector_name, vector_name, strlen(vector_name))==0){
            if(strlen(vector_name) == strlen(temp->vector_name))
                break;
        }
        temp = temp->next;
    }

    if(temp != NULL){
        temp->ref_count = temp->ref_count -1;
      ref_cnt = temp->ref_count;
        module_put(temp->vector_module);
    }
    mutex_unlock(&list_lock);
out:
    return ref_cnt;
}
EXPORT_SYMBOL(reduce_ref_count);

struct file_operations proc_fops = {
.read = show_vectors
};

int init_module(void){
    int ret = 0;
    pde = proc_create(filename, 0444, 0, &proc_fops);
    if(IS_ERR(pde)){
        ret = PTR_ERR(pde);
        goto out;
    }
    //pde->read_proc = show_vectors;
    mutex_init(&list_lock);
    out:
    return ret;
}

void cleanup_module(void){
    remove_proc_entry(filename, 0);
}
