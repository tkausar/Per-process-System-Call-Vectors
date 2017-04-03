#define _GNU_SOURCE
#include "../vec_ioctl/ioctl_proc.h"
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "/usr/src/hw3-cse506p01/include/uapi/linux/sched.h"

#define errExit(msg) 	do{ perror(msg); exit(EXIT_FAILURE);}while(0)


#define MAX_FILENAME 512
#define MAX_VECTOR_NAME_LEN 256
#define STACK_SIZE 1024*1024

int ioctl_set_vector(int file_desc, char* addr){
        int ret = 0;
        ret = ioctl(file_desc, IOCTL_SET_VECTOR, addr);
        if(ret < 0){
                printf("ioctl_set_vector failed:%d\n", file_desc);
                perror("ERROR ");
        }
        return ret;
}

int ioctl_remove_vector(int file_desc, char* addr)
{
        int ret = 0;

        ret = ioctl(file_desc, IOCTL_REMOVE, addr);
        if (ret < 0) {
                printf("ioctl_remove_vector failed:%d\n", file_desc);
                perror("ERROR ");
        }
        return ret;
}


static int childFunc(void *arg){
	char *buf;
	int ret;
	int fd;
	char proc[] = "/dev/ioctl_device";
	char *file_name;
	int file_desc;
	file_name = (char*)malloc(MAX_FILENAME);
        memset(file_name, 0, MAX_FILENAME);
        memcpy(file_name, proc, strlen(proc));
	file_desc = open(file_name,0);
	fd = open("sample.txt", O_RDWR, 777);
	buf = (char *)malloc(500);
	ret = read(fd, buf, 200);
	printf("Read buffer by child- %s\n", buf);
//	printf("vector name /file desc : %s, %d\n",(char *)arg, file_desc);	if(arg != 0){
//		ret = ioctl_remove_vector(file_desc, (char *)arg);
//	}
	free(file_name);
	ret = close(fd);
	ret = close(file_desc);
	return 0;
}

int main(int argc, char *argv[]){
	char *stack;
	char *stackTop;
	pid_t pid;
	char proc[] = "/dev/ioctl_device";
        char *file_name;
        char *vector_name;
	char *buf;
	int fd;
	int ret;
	int file_desc;
	
        if(argc < 2){
                printf("Please enter appropriate number of arguments\n");
                goto out;
        }
	stack = malloc(STACK_SIZE);
	if(stack == NULL)
		errExit("malloc");
	stackTop = stack + STACK_SIZE;
	/*setting parent process's syscall vector*/
	file_name = (char*)malloc(MAX_FILENAME);
        memset(file_name, 0, MAX_FILENAME);
        memcpy(file_name, proc, strlen(proc));
	
	vector_name = (char*)malloc(MAX_VECTOR_NAME_LEN);
        memcpy(vector_name, argv[1], strlen(argv[1]));

	file_desc = open(file_name,0);
        if(file_desc < 0){
        	printf("can't open file: %s\n",file_name);
	        goto free_out;
        }
	ret = ioctl_set_vector(file_desc, vector_name);
        if(ret < 0){
        	goto free_out;
        }
        fd = open("sample.txt", O_RDWR, 777);
        buf = (char *)malloc(500);
	ret = read(fd, buf, 200);
 	printf("Read buffer by parent- %s\n", buf);
	
	pid = clone(childFunc, stackTop, CLONE_SYSCALLS|SIGCHLD, (void *)vector_name);
//	pid = clone(childFunc, stackTop, SIGCHLD, 0);
	if(pid == -1){
		errExit("clone");
		printf("clone() returned %ld\n", (long) pid);
	}
	sleep(1);
	if (waitpid(pid, NULL, 0) == -1)    /* Wait for child */
           errExit("waitpid");
           printf("child has terminated\n");
	ret = close(fd);
//	printf("parent removing vector %s, %d\n",vector_name, file_desc);
        ret = ioctl_remove_vector(file_desc, vector_name);
        if(ret < 0) {
                goto free_out;
        }
        close(file_desc);
	
free_out:
        if(buf != NULL){
                free(buf);
        }

        free(file_name);
        free(vector_name);
out:
        return ret;
}
