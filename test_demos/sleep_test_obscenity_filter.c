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
	char *vector_name = NULL;
	int file_desc;
	char *buf = NULL;
	
  if((argc < 2) || (strlen(argv[1]) > MAX_VECTOR_NAME_LEN)){
		printf("Invalid number of arguments\n");
    goto out;
	}

	printf("\nTesting \"file_ops_vector\"\n");
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
	
  fd = creat("sample_dog.txt", 777);
	if (fd < 0)
  {
    printf("Creat: Creation of file is blocked due to obscene name, fd=%d\n", fd);
//    goto free_out2;
  }

  fd = creat("sample_do.txt", 777);

  fd = open("sample_dog.txt", O_CREAT, 777);
	if (fd < 0)
  {
    printf("Open: Creation of file is blocked due to obscene name, fd=%d\n", fd);
  //  goto free_out2;
  }
  
  fd = open("sample.txt", O_RDWR, 777);
  
  buf = (char *)malloc(500);
  
  ret = read(fd, buf, 200);
  printf("Read buffer- %s\n", buf);
  
  strcpy(buf,"Smith is a dog. He is also a donkey.");
  ret = write(fd, buf, strlen(buf));
  printf("write buffer- %s\n", buf);

  ret =  fchown(fd, 1234 , 33); //doing write internally 
  if (ret < 1){
    printf("File ownership cannot be changed to blocked user\n");
//    goto free_out2;
  }
  
  ret =  fchown(fd, 12345 , 33); //doing write internally 

  ret = close(fd);

  sleep(100);

free_out2:
/*
  ret = ioctl_remove_vector(file_desc, vector_name);
	if(ret < 0) {
		goto free_out;
	}
*/
  if (file_desc)
  	close(file_desc);

free_out:
	if(buf != NULL){
		free(buf);
	}		

  if(file_name)
	  free(file_name);
	
  if (vector_name)
    free(vector_name);
out:
	return ret;
}
