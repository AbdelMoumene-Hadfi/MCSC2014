/* there is no memory corruption on this 
 * so don't waste your time 
 * try to execute something with system()... wait , you've only 
 * five chars to do that
 * good luck
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


#define for_each_iface(curr) \
	for(;(curr);(curr)=(curr)->ifa_next)

#define PORT 1234

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


int handle_clients(int sockfd,int (*client_t)(int sockfd))
{
	int clifd;
	struct sockaddr_in cli_addr;
	socklen_t ca_len;
	pid_t child;
	
	for(;;) {
		clifd = accept(sockfd,NULL,NULL);
		if (clifd == -1) 
			continue;
		child = fork();
		switch (child) {
		case 0:
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

int send_string(int fd,char *buf)
{
	size_t len = strlen(buf);
	return write(fd,buf,len);
}

void sig_alarm(int sig)
{
	printf("[timeout] alarm\n");
	exit(0);
}

int dropshell(int fd)
{
	char buf[100]={0};
	
	alarm(20);
	signal(SIGALRM,sig_alarm);

	send_string(fd,"[+] Type a Command : ");
	
	
	size_t rc = read(fd,buf,5);
	if (rc <= 0) {
		close(fd);
		exit(1);
	}
	system(buf);
	

}

int main(int argc, char **argv)
{
	char *iface;
	int fd;

	iface = (argc > 1)?argv[1]:"eth0";

	fd = create_socket(iface,PORT);
	handle_clients(fd,dropshell);
	
	return 0;
	
}

