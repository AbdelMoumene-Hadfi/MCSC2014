/* 
 *   time for interesting stuff  :')
 *   Pwnable500 by Mohamed Ghannam (simo36) MCSC 2014
 *   64-bit executable + NX + ASLR 
 *   Compilation : gcc -o pwn500 pwn500.c -ljson -std=c99 -fno-stack-protector -ggdb -znoexecstack 
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
#include <json/json.h>

#define TITLE_SIZE	20
#define DESC_SIZE	128

#define for_each_iface(curr) \
	for(;(curr);(curr)=(curr)->ifa_next)

#define PORT 13371

/* global structure */
struct book {
	unsigned int id;
	unsigned char title[20];
	unsigned char description[256];
}book_store[256];

enum book_stat {
	TITLE_SET=1,
	DESC_SET=2,
};
	

size_t list_string_size = 4096;
unsigned int id_book=0;

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
		clifd = accept(sockfd,(struct sockaddr*)&cli_addr,&ca_len);
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

int do_read(int fd, char *buffer, size_t size)
{
	
	int readbytes = -1;
	
	if ( buffer == NULL ) {
		return -1;
	}

	if ( size == 0 ) {
		return 0;
	}

	readbytes = read( fd, buffer, size );

	return readbytes;
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

void show_list(int fd)
{
	int i;
	char *list = (char *)malloc(list_string_size);
	memset(list,0,list_string_size);
	if (!list) {
		perror("[error] malloc()");
		close(fd);
		exit(0);
	}
	int rc = snprintf(list,list_string_size,
			  "+-------------------------------------------------------------------------+\n"
			  "+ %5s   | %5s   | %5s \t\t \n"
			  "+-------------------------------------------------------------------------+\n"
			  ,"id","title","description");
	list_string_size-=(size_t)rc;
	size_t nbytes=rc;
	
	for(i=0;i<id_book;i++) {

		rc = snprintf(list+nbytes,list_string_size,
			      "+-----------------------------------------------------------------------+\n"
			      "+ %-5d   | %-20s  | %-20s \t\t \n"
			      "+-----------------------------------------------------------------------+\n"
			      ,book_store[i].id,book_store[i].title,book_store[i].description);
		nbytes+=rc;
		list_string_size-=rc;
		if (nbytes >= list_string_size) {
			list = realloc(list,list_string_size*2);
			list_string_size*=2;
		}

	}
	
	send_string(fd,list);
	free(list);
	list = NULL;
	
}
json_object *jobj;
int  parse_request(int fd)
{
	struct book *curr,store;	
	char *value;

	char *req;
	

	char *src,*ptr;
	enum json_type js_type;
	enum book_stat stat=0;
	unsigned int integer;
	unsigned char unicode[4];
	size_t vlen,tlen,dlen;
	char buf[256];	
	
	
	req = malloc(4096*sizeof(char));
	if(!req) {
		close(fd);
		exit(0);
	}
	memset(req,0,4096);
	
	send_string(fd,"[*] send your json file : ");
	size_t nbytes = read(fd,req,4095);
	
	jobj = json_tokener_parse(req);
	if(!jobj) {
		send_string(fd,"\n[error] Invalid Json script ! try again\n\n");
		goto out;
	}
	
	curr = (struct book*)mmap(0,sizeof(struct book),PROT_WRITE|PROT_READ,
				  0x22 ,-1,0);
	memset(curr,0,sizeof(struct book));

	if(curr == (struct book*)-1) {
		perror("[error] mmap()");
		close(fd);
		exit(-1);
	}

	json_object_object_foreach(jobj,key,val) {
		js_type = json_object_get_type(val);
		
		switch(js_type) {
		case json_type_double:
		case json_type_boolean:
		case json_type_int:
			break;
			
		case json_type_string:

			src = (char *)json_object_get_string(val);
			
#if 0
			printf("src :%s\n",src);
#endif
						
			vlen = strlen(src);
			ptr = src;
			dlen=0;
			
			/*
			while (*src) {
				/* Javasript shellcode ;-) 
				if(*src == '\\') {
					*src++;
					switch(*src) {
						*ptr++ = *src++;
						break;
					case 'u':
						src++;
						printf("src : %s\n",src);
						memcpy(unicode,src,4);
						src+=4;
						printf("src : %s\n",src);
						integer = strtoul(unicode,NULL,16);
						*ptr++= (integer >> 8) & 0xff;
						*ptr++= (integer & 0xff);
						
						printf("hehe hex : %08x\n",integer);
						break;
					default:
						send_string(fd,"[*] Encoding Error\n");
						goto out;
					}
				}
				
				
				else
					*ptr++ = *src++;
			}
			*/
			if(!strncmp(key,"title",strlen("title"))) {
				if (~(stat & TITLE_SET)) {
					tlen = (vlen >= TITLE_SIZE)?TITLE_SET-1:vlen;
					memcpy(store.title,src,tlen);
					stat |= TITLE_SET;
				}
			}
			
			if(!strncmp(key,"description",strlen("description"))) {
				if(~(stat & DESC_SET)) {
					dlen = strlen(src);
					// BUG
					
					memcpy(store.description,src,strlen(src));
					stat|= DESC_SET;
					
				}
			}
			
			break;
		default:
			break;
		}
	}

	if (!(stat & DESC_SET) || !(stat & TITLE_SET)) {
		send_string(fd,"[parsing error] book information is incomplete ! please try again");
		goto out;
	}
	//memcpy(&book_store[id_book],&store,sizeof(struct book));
#if 0

	printf("id : %d\n",book_store[id_book].id);
	printf("title :%s\n",book_store[id_book].title);
	printf("description :%s\n",book_store[id_book].description);
#endif
	id_book++;


out:
	return 0;

}
int menu(int fd)
{
	char opt[10]={0};
	int choice;
	int i;
	
	for(i=0;i<sizeof(book_store);i++)
		memset(&book_store[0],0,sizeof(struct book));
	
	alarm(20);
	signal(SIGALRM,sig_alarm);

	send_string(fd,"\t\t=========[ Welcome to Book-Store ]=========\n");
		
	for(;;) {
		send_string(fd,"[*] Please choose an option:\n");
		send_string(fd,"1: add a Book\n");
		send_string(fd,"2: list all the books\n");
		send_string(fd,"3: Quit\n>>> ");
		
		size_t rc = read(fd,opt,2);
		if (rc <= 0) {
			close(fd);
			exit(1);
		}
		choice = opt[0] - '0';
		
		switch(choice) {
		case 1:
			parse_request(fd);
			break;
		case 2:
			show_list(fd);
			break;
		case 3:
			printf("quit\n");
			close(fd);
			exit(0);
			break;
		}

	}

}

int main(int argc, char **argv)
{
	char *iface;
	int fd;
	

	iface = (argc > 1)?argv[1]:"eth0";

	fd = create_socket(iface,PORT);
	handle_clients(fd,menu);
	
	return 0;
	
}

