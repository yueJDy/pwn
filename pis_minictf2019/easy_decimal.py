from pwn import *
host, port = "34.80.245.238", 44445
a = remote(host, port)
result = 0
a.recvuntil('how about you?')
while 1:
	x = 0
	y = 0
	count = 0
	a.recvuntil(':')
	res = a.recv(20)
	print res
	if res[0] == 't':
		break
	for i in res:
		if i == "=":
			break
		if i == "\n":
			continue
		if i == " " :
			count += 1
			continue
		else:
			if count == 0:
				x = x*10 + int(i)
			if count == 1:
				dau = i
			if count == 2:
				y = y*10 + int(i)
	if dau == "+":
		result = x + y
	elif dau == "-":
		result = x - y
	elif dau == "*":
		result = x * y
	elif dau == "/":
		result = x / y
	a.sendline(str(result))
a.interactive()