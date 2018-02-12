#!/bin/bash
bname=`basename $1`
filename=`echo $bname|cut -d . -f1`
echo "compiling..."
gcc -fno-stack-protector -z execstack -g $bname -o $filename.exe
