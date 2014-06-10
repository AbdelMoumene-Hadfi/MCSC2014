/*
 * pwn300 by Mohamed Ghannam (simo36) MCSC2014
 * security features :  ASLR + SSP
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <ifaddrs.h>
#include <errno.h>
#include <net/if.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <syslog.h>

#define PORT 12345
#define for_each_iface(curr) \
	for(;(curr);(curr)=(curr)->ifa_next)


int handle_clients(int sockfd,int (*client_t)(int sockfd))
{
	int clifd;
	struct sockaddr_in cli_addr;
	socklen_t ca_len;
	pid_t child;
	
	for(;;) {
		clifd = accept(sockfd,(struct sockaddr*)NULL,NULL);
		if (clifd == -1) 
			continue;
		child = fork();
		switch (child) {
		case 0:
			dup2(clifd,0);
			dup2(clifd,1);
			dup2(clifd,2);

			close(sockfd);
			client_t(clifd);
			close(clifd);
			exit(0);
			break;
		case -1:
			perror("[error] fork()");
			exit(0);
		default:
			close(clifd);
			break;
		}
		
		
	}
}

int create_socket(const char *iface,unsigned short port)
{
	int sfd,rc,optval=1;
	struct ifaddrs *ifa;
	
	signal(SIGCHLD,SIG_IGN);
	
	sfd = socket(AF_INET,SOCK_STREAM,0);
	if(sfd == -1) {
		perror("[error] socket()");
		exit(sfd);
	}
	
	if(setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR,&optval,sizeof(optval)) == -1) {
		perror("[error] setsockopt()");
		exit(sfd);
	}

	rc = getifaddrs(&ifa);
	if(rc) {
		perror("[error] getifaddrs()");
		exit(-1);
	}
	struct ifaddrs *curr = ifa;
	struct ifaddrs *walker = ifa;

	for_each_iface(curr) {
		if (curr->ifa_addr->sa_family == AF_INET)  {
			if(!strcmp(curr->ifa_name,iface)) {
				((struct sockaddr_in *)(curr->ifa_addr))->sin_port = htons( port);
				rc = bind(sfd,curr->ifa_addr,sizeof(struct sockaddr_in));
				if (rc == -1) {
					perror("[error] bind()");
					exit(-1);
				}
				break;
			}
		}
	
	}
	if(!curr) {
		printf("[error] failed to bind() to %s\n",iface);
		exit(1);
	}
	
	if(listen(sfd,0x10) == -1) {
		perror("[error] listen()");
		exit(2);
	}
	
	return sfd;
}

int send_string(int fd,char *buf)
{
	size_t len = strlen(buf);
	return write(fd,buf,len);
}

char buf[512]={0};
int client(int fd)
{
	char name[512]={0};
	
	size_t nbytes;
	printf("======================================\n");
	printf("Pwnable 300pts by Simo36\n");
	printf("Protections : ASLR + SSP\n");
	printf("======================================\n");
	printf("your name :");
	nbytes = read(fd,name,510);

	if(nbytes < 0) {
		perror("read()");
		close(fd);
		exit(0);
	}
	memcpy(buf,name,nbytes);
	//syslog(LOG_USER|LOG_DEBUG,"YOOOOOOOOOOO %s\n",name);
	printf("Welcome ");
	printf(name);
	printf("\n");
}
int main(int argc,char **argv)
{
	int fd;
	char *iface;
	//alarm(10);
	//signal(SIGALRM,sig_alarm);

	setvbuf(stdout,NULL,_IONBF,BUFSIZ);
	setvbuf(stdin,NULL,_IONBF,BUFSIZ);
	setvbuf(stderr,NULL,_IONBF,BUFSIZ);

	iface = (argc > 1)?argv[1]:"eth0";
	
	fd = create_socket(iface,PORT);
	dup2(fd,0);
	dup2(fd,1);
	dup2(fd,2);
	handle_clients(fd,client);
	
}
