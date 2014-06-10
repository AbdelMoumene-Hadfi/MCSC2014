/* 
 * Ce n'est pas le code vulnérable 
 * C'est une simple demonstration de l'utilisation de l'appelle systeme segmap()
 * le code vulnérable est dans  segmap.patch 
 * 
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <pthread.h>

#define SYS_segmap		313
#define SEGMAP_GET		1
#define SEGMAP_INSERT		2
#define SEGMAP_REMOVE		4
#define SEGMAP_MASK		15

#define SEGMAP_MAX_VMA		128
struct mmap_arg_struct {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offset;
};

struct segmap {
	pid_t sm_pid;
	char sm_comm[16];
	struct  {
		unsigned long start_code,end_code;
		unsigned long start_data,end_data;
		unsigned long stack;
		int nr_vma;
		struct vm {
			unsigned long vm_start,vm_end;
		}vm[SEGMAP_MAX_VMA];			/* used to hold other memory allocations
							 * BSS section,dynamically allocated chunks ... etc */
	}pmem;						/* Process memory holder*/
	struct mmap_arg_struct mmap;
/* Some Macro facilities */
#define sm_vm			pmem.vm
#define sm_start_code		pmem.start_code
#define sm_end_code		pmem.end_code
#define sm_start_data		pmem.start_data
#define sm_end_data		pmem.end_data
#define sm_stack		pmem.stack
#define sm_nr_vma		pmem.nr_vma
#define sm_vm_vmstart		sm_vm.vm_start
#define sm_vm_vmend		sm_vm.vm_end
#define sm_vm_vmnext		sm_vm.next

};
#define BASE ((void*)0x80000000)
int *nr;

void *do_stuff(void *args)
{
	*nr = 0x41414141;
	
}

void do_segmap(pid_t pid,struct segmap *sgmap,unsigned long *state,int flags)
{
	
	int ret = syscall(SYS_segmap,pid,sgmap,state,flags);	
	if(ret == -1) {
		perror("segmap");
		exit(0);
	}

}
void segmap_output(struct segmap sgmap)
{
	int vma_i=0;
	printf("[+] pid : %d (%s) \n",sgmap.sm_pid,sgmap.sm_comm);
	printf("[+] code : 0x%.lx-0x%.lx\n",sgmap.sm_start_code,sgmap.sm_end_code);
	printf("[+] data : 0x%.lx-0x%.lx\n",sgmap.sm_start_data,sgmap.sm_end_data);
	printf("[+] nr_vma: %d \n",sgmap.sm_nr_vma);
	
	// we've recently added nr_vma to segmap struct 
	for(vma_i=0;vma_i<sgmap.pmem.nr_vma;vma_i++) 
		printf("[+] mmaped %lx-%lx\n",sgmap.sm_vm[vma_i].vm_start,sgmap.sm_vm[vma_i].vm_end);

}
int main(int argc,char **argv)
{
	struct segmap sgmap;
	unsigned long target;
	size_t len = 0x2000;
	char *addr;
	pid_t pid;
	int ret;
	int nr_vma = 5;
	int vma_i;
	unsigned long  *state,val;
	if(argc < 2 ) {
		printf("%s <pid>  \n",*argv);
		return -1;
	}
	pid = atoi(argv[1]);
	
	do_segmap(pid,&sgmap,&val,SEGMAP_GET);	
	segmap_output(sgmap);
	
	sgmap.mmap.fd = -1;
	sgmap.mmap.addr = 0x900000;
	sgmap.mmap.flags = 0x32;
	sgmap.mmap.prot = 7;
	sgmap.mmap.len=4096;
	
	do_segmap(pid,&sgmap,&val,SEGMAP_INSERT);	
	do_segmap(pid,&sgmap,&val,SEGMAP_GET);	
	segmap_output(sgmap);
	return 0;
}
