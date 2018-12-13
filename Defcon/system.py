from pwn import *

elf = ELF("/lib/x86_64-linux-gnu/libc.so.6")

print(elf.symbols['system'])
