#include "../vec_ioctl/ioctl_proc.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>    
#include <unistd.h>  
#include <sys/ioctl.h>    
#include <string.h>
#include <errno.h>

#define MAX_FILENAME 512
#define MAX_VECTOR_NAME_LEN 256
#define oldname "test_file_secure_link"
#define newname "test_file_secure_link_new"
#define pathname "test_file_secure_unlink"
#define oldname2 "test_file_secure_link_protect"
#define newname2 "test_file_secure_link_protect_new"
#define pathname2 "test_file_secure_unlink_protect"
#define makedirname "test_make_dir"
#define makedirname2 "test_make_dir_protect"
#define rmdirname "test_remove_dir"
#define rmdirname2 "test_remove_dir_protect"
#define chmod_file_name "test_chmod_file"
#define chmod_file_name2 "test_chmod_file_protect"
#define mode 700
#define RET_VAL 0

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

  ret = ioctl_set_vector(file_desc, vector_name); //Setting vector 
  if(ret < 0){
    goto free_out;
  }
  else
  printf("Vector %s is set \n-------------------------------------------------\n",vector_name);
  printf("\nTEST 1  :");
  printf("\nTesting link syscall without protect keyword:-\n");
  fd = open(oldname,O_CREAT,777);
  ret = link(oldname,newname);
  if(ret==1000)
  {
    printf("Operation Disabled : You are not allowed to link this file %s\n",oldname);
  }
  else if(ret==RET_VAL)

  printf("Link successful for (%s, %s)\n",oldname,newname);

  printf("\nTesting link syscall with protect keyword:-\n");
  fd = open(oldname2,O_CREAT,777);
  ret = link(oldname2,newname2);
  if(ret==1000)
  {
    printf("Operation Disabled : You are not allowed to link this file %s [contains protect keyword]\n",oldname2);
  }
  else if(ret==RET_VAL)
  printf("Link successful for (%s, %s)\n",oldname2,newname2);

  printf("\nTEST 2 :");
  printf("\nTesting unlink syscall without protect keyword\n");
  fd = open(pathname,O_CREAT,777);
  ret = unlink(pathname);
  if(ret==1000)
  {
    printf("Operation Disabled : You are not allowed to unlink the file %s\n",pathname);
  }
  else if(ret ==RET_VAL)
    printf("Unlink successful for %s\n",pathname);

  printf("\nTesting unlink syscall with protect keyword\n");
  fd = open(pathname2,O_CREAT,777);
  ret = unlink(pathname2);
  if(ret==1000)
  {
    printf("Operation Disabled : You are not allowed to unlink the file %s [contains protect keyword]\n",pathname2);
  }
   else if(ret ==RET_VAL)
     printf("Unlink successful for %s\n",pathname);
  
  printf("\nTEST 3:");
  printf("\nTesting mkdir syscall without protect keyword\n");
  ret = mkdir(makedirname,777);
  if(ret==1000)
  {
    printf("Operation Disabled : You are not allowed to create directory %s with protect keyword\n",makedirname);
  }
   else if(ret ==RET_VAL)
        printf("Makedir successful for %s\n",makedirname);


  printf("\nTesting mkdir syscall with protect keyword\n");
  ret = mkdir(makedirname2,777);
  if(ret==1000)
  {
    printf("Operation Disabled : You are not allowed to create directory %s with protect keyword \n",makedirname2);
  }
   else if(ret ==RET_VAL)
     printf("Makedir successful for %s\n",makedirname2);

 printf("\nTEST 4:");
  printf("\nTesting rmdir syscall without protect keyword\n");
  ret = mkdir(rmdirname,777);
  ret = rmdir(rmdirname);
  if(ret==1000)
  {
    printf("Operation Disabled : You are not allowed to remove directory %s with protect keyword\n",rmdirname);
  }
   else if(ret ==RET_VAL)
     printf("Rmdir successful for %s\n",rmdirname);


  printf("Testing rmdir syscall with protect keyword\n");
  ret = mkdir(rmdirname,777);
  ret = rename(rmdirname,rmdirname2);
  ret = rmdir(rmdirname2);
  if(ret==1000)
  {
    printf("Operation Disabled : You are not allowed to remove directory %s with protect keyword \n",rmdirname2);
  }
  else if(ret ==RET_VAL)
    printf("Rmdir successful for %s\n",rmdirname2);
 
 printf("\nTEST 5:");
  printf("\nTesting chmod syscall without protect keyword\n");
  ret = open(chmod_file_name,O_CREAT,777);
  ret = chmod(chmod_file_name,mode);
  if(ret==1000)
  {
    printf("Operation Disabled : You are not allowed to change permission for  %s [ protect keyword] \n",chmod_file_name2);
  }
  else if(ret ==RET_VAL)
    printf("Chmod successful for %s\n",chmod_file_name);


  printf("Testing chmod syscall with protect keyword\n");
 // ret = mkdir(rmdirname,777);
  ret = rename(chmod_file_name,chmod_file_name2);
  ret = chmod(chmod_file_name2,mode);
  if(ret==1000)
  {
    printf("Operation Disabled : You are not allowed to change permission for  %s [ protect keyword] \n",chmod_file_name2);
  }
  else if(ret ==RET_VAL)
    printf("Chmod successful for %s\n",chmod_file_name2);


  ret = ioctl_remove_vector(file_desc, vector_name);   //removing dependency from vector on exit
  if(ret < 0) {
    goto free_out;
  }
  else 
  printf("\nRemoved the vector %s\n",vector_name);

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

