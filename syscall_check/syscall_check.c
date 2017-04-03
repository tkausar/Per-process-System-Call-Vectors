#include<asm/signal.h>
#include<asm/thread_info.h>
#include<asm/errno.h>
#include<asm/unistd.h>
#include<asm/current.h>
#include<linux/sched.h>
#include "../regvec/syscall.h"


#define NOT_OVERRIDDEN -9999
#define WRAPPED -8888
int64_t ret;

int syscall_inherit_check(void){
	int64_t syscall_number;
	struct syscall_vector *vec_head = NULL;
	struct syscall_vector *temp = NULL;
	struct task_struct *tsk = NULL;

	ret = NOT_OVERRIDDEN;
	asm(
		"pushq %rax\n\t"
		"pushq %rbx\n\t"
		"pushq %rcx\n\t"
		"pushq %rdx\n\t"
		"pushq %rsi\n\t"
		"pushq %rdi\n\t"
	);

	asm("movq %%rax, %0":"=r"(syscall_number): :"%rax");
	tsk = get_current();
	if(tsk->syscall_data == NULL){
		ret = NOT_OVERRIDDEN;
		goto out;
	}else{
		printk(KERN_INFO "Syscall number: %d", syscall_number);
		vec_head = (struct syscall_vector*)tsk->syscall_data;
		if(vec_head == NULL){
			ret = NOT_OVERRIDDEN;
			goto out;
		}
		temp = vec_head;
		while(temp != NULL){
			if(temp->sys_call.syscall_no == syscall_number){
				asm(
									"pushq 0x20(%ebp)\n\t"
									"pushq 0x1c(%ebp)\n\t"
									"pushq 0x18(%ebp)\n\t"
									"pushq 0x14(%ebp)\n\t"
									"pushq 0x10(%ebp)\n\t"
									"pushq 0x0c(%ebp)\n\t"
					);
				asm("movq %0, %%rax\n\t": :"r"(temp->sys_call.function_ptr) :"%rax");
				asm("call *%rax\n\t");
				asm("movq %%rax, %0":"=r"(ret): :"%rax");
				printk(KERN_INFO "Ret after function call: %d", ret);
				asm(	"popq %rbx\n\t"
					"popq %rcx\n\t"
					"popq %rdx\n\t"
					"popq %rsi\n\t"
					"popq %rdi\n\t"
					"popq %rax\n\t"
					);

				break;
			}else{
				ret = NOT_OVERRIDDEN;
			}
			temp = temp->next;
		}
	}

out:
	asm(
		"popq %rdi\n\t"
		"popq %rsi\n\t"
		"popq %rdx\n\t"
		"popq %rcx\n\t"
		"popq %rbx\n\t"
		"popq %rax\n\t"
	);

	if(ret == WRAPPED){
		printk(KERN_INFO "This is a wrapped system call. Now, calling original system call.");
		ret = NOT_OVERRIDDEN;
	}

return ret;
}
