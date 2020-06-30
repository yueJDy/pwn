from pwn import *
import random

while 1:
    a = remote( '2019shell1.picoctf.com', 4160)
    for i in range(0,31): 
       a.recvuntil('Guess the height: ')
       # x = random.randint(0,15)
       print '11'
       # a.sendline( str(x) )
       a.sendline('11')
       if a.recv(5) == 'WRONG':
		  a.close()
		  break
    if (a.recv(3) == 'Con'):
        a.interactive()
  
