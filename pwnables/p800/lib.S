.global aMsg
aMsg:   
        .asciz "tiny ELF is a badass"

.global pwn
pwn:
        movl $3,%eax
        movl $0,%ebx
        movl %esp,%ecx
        movl $0x1000,%edx
        int $0x80
        ret

