#include "../vec_ioctl/ioctl_proc.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>    /* open */
#include <unistd.h>   /* exit */
#include <sys/ioctl.h>    /* ioctl */
#include <string.h>
#include <errno.h>

#define MAX_FILENAME 512
#define MAX_VECTOR_NAME_LEN 256
#define oldname "test_secure_1"
#define newname "test_secure_1_new"

int ioctl_set_vector(int file_desc, char* addr){
  int ret = 0;
  ret = ioctl(file_desc, IOCTL_SET_VECTOR, addr);
  if(ret < 0){
    printf("ioctl_set_vector failed:%d %d\n", errno, file_desc);
    perror("ERROR ");
  }
  return ret;
}

int ioctl_remove_vector(int file_desc, char* addr)
{
  int ret = 0;

  ret = ioctl(file_desc, IOCTL_REMOVE, addr);
  if (ret < 0) {
    printf("ioctl_remove_vector failed:%d %d\n", errno, file_desc);
    perror("ERROR ");
  }
  return ret;
}

int main(int argc, char** argv){
  int ret = 0, fd = 0;
  char proc[] = "/dev/ioctl_device";
  char *file_name;
  char *vector_name;
  int file_desc;
  char *buf;

  if((argc < 2) || (strlen(argv[1]) > MAX_VECTOR_NAME_LEN)){
    printf("Invalid number of arguments\n");
    goto out;
  }

  printf("\nTesting \"secure_vector\"\n");
  printf("My process ID : %d\n", getpid());

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
 // fd = open("test1_file", O_CREAT, 777);
 // buf = (char *)malloc(500);
 // ret = read(fd, buf, 200);
  fd = open(oldname,O_CREAT,777);
  ret = link(oldname,newname);
  if(ret==1000)
  {
     printf("Operation Disabled : You are not allowed to link this file\n");
  }

  sleep(100);
/*
  ret = ioctl_remove_vector(file_desc, vector_name);
  if(ret < 0) {
    goto free_out;
  }
*/
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

