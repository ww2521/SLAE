xor edx,edx
push word dx

pop edx
pop dx
sub dh,1

push word 0x7f00

push dx
push edx
