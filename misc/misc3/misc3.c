/* 
 * Level by simo36 for MCSC 2014
 * this is an introduction to software sandboxing
 * let's know if you skipped our sandboxed app
 * HINT : memory feetchers (aka egghunters) might help
 * compiltation : gcc -o misc3 misc3.c -lseccomp -m32 -zexecstack
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <seccomp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>


int main()
{
	char *addr;
	int fd,ret;
	char buf[20]={0};
	char sc[128]={0};
	scmp_filter_ctx ctx;

	
	ctx  = seccomp_init(SCMP_ACT_KILL);
	if (!ctx) {
		perror("seccomp_init");
		return -1;
	}
	ret = seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(write),0);
	if(ret) {
		perror("add rule");
		return -1;
	}

	ret = seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(access),0);
	if(ret) {
		perror("add rule");
		return -1;
	}
	
	fd = open("./.passwd",O_RDONLY);
	if(fd == -1) {
		perror("open");
		return -1;
	}
	read(fd,buf,20);
	
	addr = mmap(0,4096,PROT_READ|PROT_WRITE,MAP_SHARED |MAP_ANONYMOUS,-1,0);
	if (addr == (char*)-1) {
		perror("mmap");
		return -1;
	}
	
	memset(addr,0,4096);
	memcpy(addr,"MCSC",4);
	memcpy(addr+4,"2014",4);
	memcpy(&addr[8],buf,20);
	
	printf("put you shellcode here : ");
	fflush(stdout);
	
	ssize_t rc = read(0,sc,128);
	sc[rc-1]=0;
	seccomp_load(ctx);
	
	((void (*)(void))sc)();
	
	
	return 0;
}
