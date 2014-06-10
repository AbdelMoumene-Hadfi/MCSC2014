/*
	Level by  simo36 
	HINT :  it was a serious vulnerability in gnu libc. this is why I implemented
		my own (tinny)libc to prevent against it ,but the vuln is still working :-(
		pay a close look at file descriptors and how linux handles them
		let us know if you got it :-)
		the patch of this old vuln : https://sourceware.org/git/?p=glibc.git;a=blob;f=csu/check_fds.c
	compilation : gcc -o misc2 misc2.S -Os -nostdlib -m32
*/


/* syscall table  */
__NR_sys_exit:		.int   1
__NR_sys_read:		.int   3 
__NR_sys_write:		.int   4
__NR_sys_open:		.int   5
__NR_sys_close:		.int   6
__NR_sys_execve:	.int  11
__NR_sys_lseek:		.int  19
__NR_sys_geteuid:	.int  49
__NR_sys_setresuid:	.int 164

.equ STDIN,0
.equ STDOUT,1
.equ STDERR,2
.equ O_RDWR,2	
.equ SEEK_SET ,0	

.text
.global _start
_start:
	call open_secret_file
	pushl $prompt
	call strlen
	
	pushl %eax
	pushl $prompt
	pushl $STDOUT
	call _write

	pushl $0x10
	push $0
	pushl $buf
	call memset

	pushl $0x10
	pushl $buf
	pushl $STDIN
	call _read
	
	push $buf
	call strlen

	xorl %ecx,%ecx
	pushl $8
	pushl $buf
	pushl $secret
	call check_passwd

denied:
	pushl $failed_msg
	call strlen
	pushl %eax
	pushl $failed_msg
	pushl $STDOUT
	call _write
	pushl $-4
	call _exit

win:
	pushl $win_msg
	call strlen
	pushl %eax
	pushl $win_msg
	pushl $STDOUT
	call _write

	pushl $0
	pushl $args
	pushl $binsh
	call _execve
	
	push $0
	call _exit

check_passwd:
	pushl %edi
	pushl %esi
	pushl %edx
	movl 16(%esp),%edi
	movl 20(%esp),%esi
	movl 24(%esp),%edx
	movb (%edi,%ecx,1),%al
	movb (%esi,%ecx,1),%bl
	cmpb %al,%bl
	jne denied
	inc %ecx
	cmpl %edx,%ecx
	pop %edx
	pop %esi
	pop %edi
	jge win
	jmp check_passwd

open_secret_file:
	pushl $20
	pushl $0
	pushl $secret
	call memset

	push $O_RDWR
	push $secret_file
	call _open
	cmpl $0,%eax
	jl open_sf_fails
	movl %eax,sfd
	
	pushl $0x10
	pushl $secret
	pushl sfd
	call _read

	pushl $SEEK_SET
	pushl $0
	pushl sfd
	call _lseek
	
	addl $8,%esp
	ret

open_sf_fails:
	pushl $-3
	call _exit
	
/***************************************************************/
	/****************** a MINI LIBC *******************/
	
_exit:
	movl __NR_sys_exit,%eax
	movl 4(%esp),%ebx
	int $0x80

_read:
	movl __NR_sys_read,%eax
	movl 4(%esp),%ebx
	movl 8(%esp),%ecx
	movl 12(%esp),%edx
	int $0x80
	ret $0xc
.global _write
_write:
	movl __NR_sys_write,%eax
	movl 4(%esp),%ebx
	movl 8(%esp),%ecx
	movl 12(%esp),%edx
	int $0x80
	ret $0xc

_open:
	movl __NR_sys_open,%eax
	movl 4(%esp),%ebx
	movl 8(%esp),%ecx
	movl 12(%esp),%edx
	int $0x80
	ret $0xc

_close:	
	movl __NR_sys_close,%eax
	movl 4(%esp),%ebx
	int $0x80
	ret $4

_execve:
	movl __NR_sys_execve,%eax
	movl 4(%esp),%ebx
	movl 8(%esp),%ecx
	movl 12(%esp),%edx
	int $0x80
	ret $0xc
	


_lseek:
	movl __NR_sys_lseek,%eax
	movl 4(%esp),%ebx
	movl 8(%esp),%ecx
	movl 12(%esp),%edx
	int $0x80
	ret $0xc

_geteuid:
	movl __NR_sys_geteuid,%eax
	int $0x80
	ret

_setresuid:
	movl __NR_sys_setresuid,%eax
	movl 4(%esp),%ebx
	movl 8(%esp),%ecx
	movl 12(%esp),%edx
	int $0x80
	ret $0xc

strlen:
	pushl %edi
	movl 8(%esp),%edi
	xorl %ecx,%ecx
	xorl %eax,%eax
	not %ecx
	cld
	repne scasb
	not %ecx
	dec %ecx
	movl %ecx,%eax
	popl %edi
	ret $4

memset:
	movl 4(%esp),%edi
	movb 8(%esp),%al
	movl 12(%esp),%ecx
	movl %ecx,%ebx
	rep stosb
	ret


.data
binsh:	.asciz "/bin/sh"
args:	.long binsh,0x0
prompt:	.asciz "Password: "
failed_msg:	.asciz "password is wong :-(\n"
win_msg:	.asciz "Congratz !! Dropping shell\n"
secret_file:	.asciz "/home/misc2/secret"
sfd:	.int 0
.bss
.lcomm buf,	0x10
.lcomm secret,	0x10