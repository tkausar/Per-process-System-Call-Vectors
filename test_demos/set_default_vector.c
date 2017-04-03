#include <stdio.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <unistd.h> 
#include <string.h>
#include <stdlib.h>
#include "../vec_ioctl/ioctl_proc.h"

#define MAX_PID 10

int main(int argc, char** argv){
  
  char proc[] = "/dev/ioctl_device", *vector_name;
  int pid = 0;
  int file_desc, ret = 0;

  if((argc < 2)){
    printf("Invalid number of arguments\n");
    goto out;
  }

  vector_name = (char*)malloc(MAX_PID);

  pid = atoi(argv[1]);

  file_desc = open(proc,0);
  if(file_desc < 0){
    printf("can't open file: %s\n",proc);
    goto out;
  }

  //ret = ioctl(file_desc, IOCTL_SET_VECTOR, vector_name);
  strcpy(vector_name,argv[1]);
  ret = ioctl(file_desc, IOCTL_SET_DEFAULT, vector_name);
  if (ret < 0) {
    printf("IOCTL_SET_DEFAULT failed:%d %d\n", errno, file_desc);
    perror("ERROR ");
  }

   printf("Default vector set for PID = %s\n", argv[1]);

out:  
  return ret;
}
