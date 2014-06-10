/*
  a quick warm up challenge 
  HINT : strlen() is controllable :)
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc,char **argv)
{
	int fd;
	char rand[128]={0};
	char passwd[128]={0};
	
	printf("password : ");
	fflush(stdout);
	passwd[read(0,passwd,127)]=NULL;

	fd = open("/dev/urandom",O_RDONLY);
	if(fd == -1) {
		perror("open");
		return -1;
	}
	
	ssize_t readbytes = read(fd,rand,128);
	if(readbytes != 128) 
		return -1;

	if(memcmp(rand,passwd,strlen(passwd))) {
		printf("[-] Access denied .. !\n");
		return -1;
	
	}else {
		char *args[]={"/bin/sh",NULL};
		printf("[+] Access granted .. gratz\n");
		close(0);
		dup2(2,1);
		open("/dev/tty", O_RDWR|O_NOCTTY|O_TRUNC|O_APPEND|O_ASYNC);
		execve(args[0],args,NULL);
		
	}
	return 0;
}
