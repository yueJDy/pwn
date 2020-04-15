from pwn import *

host, port = "34.80.245.238", 44444
a = remote(host, port)
while 1:
	a.recvuntil(':')
	x = a.recv(3)
	if x[1] == 'm':
		break
	print x
	x = int(x)
	a.recvuntil(':')
	y = a.recv(3)
	print y
	y = int(y)

	rs = bin(x + y)
	result = ""
	kt = 0
	for i in rs:
		if i == "b":
			kt = 1
			continue
		if kt == 1:
			result += i

	print result
	a.recvuntil('Your answer:')
	a.sendline(result)
	
a.interactive()