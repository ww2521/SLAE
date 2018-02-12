#!/bin/bash
bname=`basename $1`
filename=`echo $bname|cut -d . -f1`
echo "compiling..."
nasm -f elf32 -o $filename.o $1 
echo "linking..."
ld -o $filename.exe $filename.o
