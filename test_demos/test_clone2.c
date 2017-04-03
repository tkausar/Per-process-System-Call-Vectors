#define _GNU_SOURCE
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <asm/unistd.h>
#include "../vec_ioctl/ioctl_proc.h"
#include "../../usr/include/asm/unistd_64.h"

#define errExit(msg)    do{ perror(msg); exit(EXIT_FAILURE);}while(0)
#define __NR_clone2 329
#ifndef __NR_clone2
#error clone2  system call not defined
#endif

#define MAX_FILENAME 512
#define MAX_VECTOR_NAME_LEN 256
#define STACK_SIZE 1024*1024

int ioctl_remove_vector(int file_desc, char* addr)
{
	int ret = 0;
	ret = ioctl(file_desc, IOCTL_REMOVE, addr);
	if(ret < 0){
		printf("ioctl remove failed %d\n",file_desc);
		perror("ERROR ");
	}
	return ret;
}
void readFunc(void)
{
	char* buf;
	int ret;
	int fd;
	printf("read function called with pid %d\n", getpid());
	fd = open("sample.txt", O_RDWR, 777);
	buf = (char *)malloc(500);
	ret = read(fd, buf, 200);
	printf("read data : %s\n",buf);
	ret = close(fd);
}

int main(int argc, char *argv[]){
	int pid;
	char *vector_name;
	char proc[] = "/dev/ioctl_device";
	char *file_name;
	int file_desc;
	char *chld_vec;
	int ret;
	if(argc < 2){
		printf("Please enter appropriate number of arguments\n");
		goto out;
	}
/*	file_name = (char*)malloc(MAX_FILENAME);
        memset(file_name, 0, MAX_FILENAME);
        memcpy(file_name, proc, strlen(proc));

	file_desc = open(file_name,0);
	if(file_desc < 0){
		printf("can't open file : %s\n", file_name);
		goto out;
	}*/
	vector_name = (char *)malloc(MAX_VECTOR_NAME_LEN);
	memcpy(vector_name, argv[1], strlen(argv[1]));
	pid = syscall(__NR_clone2, (unsigned long)vector_name);
	readFunc();

	file_name = (char*)malloc(MAX_FILENAME);
        memset(file_name, 0, MAX_FILENAME);
        memcpy(file_name, proc, strlen(proc));
        file_desc = open(file_name,0);
        if(file_desc < 0){
                printf("can't open file : %s\n", file_name);
                goto out;
        }

	chld_vec = (char*)malloc(MAX_VECTOR_NAME_LEN);
	sprintf(chld_vec,"%ld",(long)getpid());
        ret = ioctl(file_desc, IOCTL_GET_VECTOR, chld_vec);
        if(ret < 0){
                printf("IOCTL_GET_VECTOR failed");
                perror("ERROR ");
        }
        printf("vector name : %s\n",chld_vec);
	sleep(30);
	if(strcmp(chld_vec,"default") != 0){
		printf("we are inside remove vec for process id %d\n",getpid());
	ioctl_remove_vector(file_desc, vector_name);
	}
	if(waitpid(pid, NULL, 0)== -1)
		errExit("waitpid");
		printf("child has terminated\n");
out:	
	return ret; 
}
