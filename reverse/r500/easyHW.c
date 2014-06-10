/*
 * Level By Simo36 
 * level password : "Emul4t0rs4r3b4d4ss.!"
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/vm86.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>

#define VM_IMAGE_SIZE	0x100000
#define BSS		0x14141 
#define BASE		0x10000
#define DATA		BASE + 0x500

char *msg="kdlfksdfjdsssssssssddddddddddd\n";

unsigned char buffer[4096]={0};

void coredump(struct vm86_regs *r)
{
	fprintf(stderr,
		"EAX=%08lx EBX=%08lx ECX=%08lx EDX=%08lx\n"
		"ESI=%08lx EDI=%08lx EBP=%08lx ESP=%08lx\n"
		"EIP=%08lx EFL=%08lx\n"
		"CS=%04x DS=%04x ES=%04x SS=%04x FS=%04x GS=%04x\n",
		r->eax, r->ebx, r->ecx, r->edx, r->esi, r->edi, r->ebp, r->esp,
		r->eip, r->eflags,
		r->cs, r->ds, r->es, r->ss, r->fs, r->gs);
}

void read_opcodes(char *file,size_t *size)
{
	int fd;
	unsigned char buf[4096]={0};
	unsigned char decoder[4096];
	int i;
	
	fd = open(file,O_RDONLY);
	if(fd == -1) {
		perror("open");
		exit(1);
	}
	
	size_t nbytes = read(fd,buffer,4096);
	if(nbytes <= 0) {
		perror("read");
		exit(2);
	}
	buffer[nbytes]='\0';
	*size = nbytes;
	close(fd);
	memcpy(decoder,buffer,nbytes);
#if 0
	fd = open("opcode.bin",O_RDWR|O_CREAT);
	if(fd == -1) {
		perror("open:");
		return ;
	}
	
	for(i=0;i<nbytes;i++) {
		printf("%02x ,",decoder[i]);
		decoder[i]+=10;
		decoder[i]^=0xaa;
		decoder[i]&=0xff;
	}
	write(fd,decoder,nbytes);
	close(fd);
#endif
}
static inline __attribute__((always_inline)) exec_asm(struct vm86_regs *r)
{
	unsigned int sysc = r->eax;
	__asm__ volatile (
		"movl %1,%%eax\n"
		"movl %2,%%ebx\n"
		"movl %3,%%ecx\n"
		"movl %4,%%edx\n"
		"movl %5,%%edi\n"
		"movl %6,%%esi\n"
		"int $0x80\n"
		"movl %%eax,%0\n"
		:"=r" (r->eax)
		:"a"(r->eax),"b"(r->ebx),
		 "c"(r->ecx),"d"(r->edx),
		 "D"(r->edi), "S"(r->esi)
		:
		);
	if(sysc == __NR_read) {
		*((u_int8_t*)r->ecx+r->eax-1)=0;
		//coredump(r);
	}

#if 0
	coredump(r);
#endif
}

int main(int argc,char **argv)
{
	struct vm86plus_struct vm;
	struct vm86_regs *regs;
	
	u_int8_t *image;
	int32_t ret,opsize;
	u_int seg;
	int32_t i;

	if(argc < 2) {
		printf("[+] Welcome to easyHW emulator\n");
		printf("Usage : %s <filename>\n",*argv);
		exit(1);
	}

	read_opcodes(*(argv+1),&opsize);	
	
	for (i=0;i<sizeof(buffer);i++) {
		buffer[i]^= 0xaa;
		buffer[i]-=10;
		buffer[i]&=0xff;
	}
	


	
	image = mmap((void*)BASE,VM_IMAGE_SIZE,7,0x22,-1,0);
	if(image == (u_int8_t *)MAP_FAILED) {
		perror("[error] mmap");
		return -1;
	}
	memset(image,0x00,VM_IMAGE_SIZE);
	memcpy(image+0x100,buffer,opsize);
	memset(&vm,0,sizeof(struct vm86_struct));
	
	vm.regs.eip = (unsigned int)(image+0x100);
	vm.regs.esp = (unsigned int)(image+0x1000);
	vm.regs.eax = 0;
	vm.regs.ebx = 0;
	vm.regs.ecx = 0;
	vm.regs.edx = strlen(msg);
	
	vm.regs.cs = ((unsigned int)image) >> 4;
	vm.regs.ss = ((unsigned int)image) >> 4;
	vm.regs.ds = ((unsigned int)image) >> 4;
	vm.regs.es = ((unsigned int)image) >> 4;
	
	vm.regs.fs = ((unsigned int)image) >> 4;;
	vm.regs.gs = ((unsigned int)image) >> 4;;
	vm.regs.eflags = 0;
	
	vm.cpu_type = CPU_586;
	
	regs = &vm.regs;

	while(1) {
		ret = vm86(VM86_ENTER,&vm);
		if (ret == -1) {
			perror("[error] vm86");
			
		}
#ifdef HW_DEBUG
		coredump(regs);
#endif

		
		//printf("return : %08x\n",ret);
		switch(VM86_TYPE(ret)) {
		case VM86_INTx:
			if (VM86_ARG(ret) != 0x80)
				break;
			if(regs->eax == __NR_write || regs->eax == __NR_read)
				regs->ecx += BASE;
			exec_asm(&vm.regs);
			break;
		case VM86_TRAP:
			exit(0);
			break;
		default:
			printf("[x] Invalid Instruction !\n");
			exit(0);
		}
		
	}
	
	return 0;
}
