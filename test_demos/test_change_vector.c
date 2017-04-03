#include "../vec_ioctl/ioctl_proc.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>		/* open */
#include <unistd.h>		/* exit */
#include <sys/ioctl.h>		/* ioctl */
#include <string.h>
#include <errno.h>

#define MAX_FILENAME 512
#define MAX_VECTOR_NAME_LEN 256
#define oldname "test_secure_1"
#define newname "test_secure_1_new"
#define obscene_name "sample_dog.txt"

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

void test()
{
  int fd, ret;

  unlink(oldname);
  unlink(newname);
  unlink(obscene_name);

  fd = creat(obscene_name, 777);
  if (fd < 0)
  {
    printf("Creat: Creation of file is not allowed due to obscene name, fd=%d\n", fd);
  }
  else {
    printf("Creat: Creation of file is successful, fd=%d\n", fd);

  }


  fd = open(oldname,O_CREAT,777);
  ret = link(oldname,newname);
  if (ret == 0) {
    printf ("Linking is successful for file: %s\n", oldname);
  }
  else if(ret==1000)
  {
    printf("Operation Disabled : You are not allowed to link this file\n");
  }

  close(fd);
}

int main(int argc, char** argv){
	int ret = 0, fd = 0;
	char proc[] = "/dev/ioctl_device";
	char *file_name;
	char *vector_name = NULL;
	int file_desc;
	
	printf("\nTesting change vector\n");
	printf("My process ID : %d\n", getpid());
	
	file_name = (char*)malloc(MAX_FILENAME);
	memset(file_name, 0, MAX_FILENAME);
	memcpy(file_name, proc, strlen(proc));
	
  vector_name = (char*)malloc(MAX_VECTOR_NAME_LEN);
	
  file_desc = open(file_name,0);
	if(file_desc < 0){
	printf("can't open file: %s\n",file_name);
	goto free_out;
	}

  strcpy(vector_name, "obscenity_filter");

	ret = ioctl_set_vector(file_desc, vector_name);
	if(ret < 0){
	goto free_out;
	}

  printf("\nCurrent vector - %s\n", vector_name);
  test();

	ret = ioctl_remove_vector(file_desc, vector_name);
	if(ret < 0) {
		goto free_out;
	}

/* change vector */

  strcpy(vector_name, "secure_vector");

  ret = ioctl_set_vector(file_desc, vector_name);
  if(ret < 0){
    goto free_out;
  }

  printf("\n\nCurrent vector - %s\n", vector_name);
  test();

  ret = ioctl_remove_vector(file_desc, vector_name);
  if(ret < 0) {
    goto free_out;
  }

  if (file_desc)
  	close(file_desc);

free_out:
  if(file_name)
	  free(file_name);
	
  if (vector_name)
    free(vector_name);
out:
	return ret;
}
