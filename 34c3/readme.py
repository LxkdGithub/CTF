#coding:utf-8

from pwn import *

p = process("./readme_revenge")
p.send("121212")
print(p.recv(100))
p.interactive()
