;; opcode.bin 
BITS 16
ORG 0x100

_start:
	mov eax,172
	mov ebx,3
	int 0x80
	cmp eax,2
	je anti_debug
	mov edi,prompt
	call strlen
	mov edx,eax
	
write_prompt:	
	mov al,4
	mov bl,1
	mov ecx,prompt
	int 0x80

read_passwd:	
	mov al,3
	mov bl,0
	mov ecx,0x500
	mov edx,100
	int 0x80


check_passwd_len:
	mov edi,0x500
	call strlen
	cmp eax,20
	jne invalid

	
check_passwd:
	xor eax,eax
	xor ecx,ecx
	xor ebx,ebx
	xor edx,edx
	
	mov edi,0x500
	mov esi,passwd
	
loop:
	cmp ecx,20
	jz correct
	mov ebx,edi
	mov edx,esi
	add ebx,ecx
	add edx,ecx
	mov bl,byte [ebx]
	mov dl,byte [edx]
	xor bl,0xcd
	sub bl,1
	cmp bl,dl
	jnz invalid
	inc ecx
	jmp loop


	mov al,4
	mov bl,1
	mov ecx,0x500
	mov edx,edi
	int 0x80
	db 0xcc

invalid:
	mov edi,invalid_passwd
	call strlen
	mov edx,eax
	mov eax,4
	mov ebx,1
	mov ecx,invalid_passwd
	int 0x80
	db 0xcc

correct:
	mov edi,correct_passwd
	call strlen
	mov edx,eax
	mov eax,4
	mov ebx,1
	mov ecx,correct_passwd
	int 0x80
	db 0xcc
	
strlen:
	push edi
	xor ecx,ecx
	xor eax,eax
	not ecx
	cld
	repne scasb
	not ecx
	dec ecx
	mov eax,ecx
	pop edi
	ret
anti_debug:
	mov edi,antidebug
	call strlen
	mov edx,eax
	mov eax,4
	mov ebx,1
	mov ecx,antidebug
	int 0x80
	int 3
	
section .data
prompt:	db "[~] Password : ",0
invalid_passwd:	db "[x] Password Invalid x(",0xa,0
correct_passwd:	db "[+] Congratz .... you WIN !!",0xa,0
passwd:	db 0x87, 0x9f, 0xb7, 0xa0, 0xf8, 0xb8, 0xfc, 0xbe, 0xbd, 0xf8, 0xbe, 0xfd, 0xae, 0xf8, 0xa8, 0xf8, 0xbd, 0xbd, 0xe2, 0xeb
antidebug:	db "[x] anti-debug shit ....!",0xa,0

section .bss
user: resb 100

