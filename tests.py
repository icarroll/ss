>>> from ss import *

>>> mem = Memory(2**20)
>>> mem[12345] = 47
>>> mem[12345]
47
>>> mem[12346]
0
>>> mem(16)[12345]
47
>>> mem(16)[12344]
12032
>>> mem(8)[12344]
0
>>> mem(16)[47] = 0xbeef
>>> hex(mem[48])
'0xbe'
>>> hex(mem[47])
'0xef'
>>> mem(32)[47] = 0xdeadbeef
>>> [hex(mem[n]) for n in range(47,47+4)]
['0xef', '0xbe', '0xad', '0xde']
>>> [hex(mem(16)[n]) for n in range(47,47+4,2)]
['0xbeef', '0xdead']


>>> mem = Memory(2**20)
>>> init_heap(mem, 2**16, 2**16)
>>> mem(24)[HEAP_START]
65536
>>> mem(24)[HEAP_END]
131072
>>> heap_ok(mem)
True

>>> init_heap(mem, 3*2**17, 2**19)
>>> mem(24)[HEAP_START]
393216
>>> mem(24)[HEAP_END]
917504
>>> heap_ok(mem)
True


>>> START, SIZE = 3*2**17, 2**19
>>> mem = Memory(2**20) ; init_heap(mem, START, SIZE)
>>> size1 = 9
>>> addr1 = allocate(mem, DATA_BLOCK, size1)
>>> START <= addr1 <= START + SIZE - size1
True
>>> size2 = 50
>>> addr2 = allocate(mem, POINTER_BLOCK, size2)
>>> addr2 >= addr1 + size1
True
>>> block_size(mem, addr1) == size1
True
>>> block_size(mem, addr2) == size2
True
>>> block_kind(mem, addr1) is DATA_BLOCK
True
>>> block_kind(mem, addr2) is POINTER_BLOCK
True
>>> for addr in range(addr1, addr1+size1):
...   mem[addr] = 255 - mem[addr]
>>> block_kind(mem, addr2) is POINTER_BLOCK
True
>>> heap_ok(mem)
True

>>> mem = Memory(256) ; init_heap(mem, 16, 240)
>>> heap_ok(mem)
True
>>> allocate(mem, DATA_BLOCK, 1000)
0
>>> heap_ok(mem)
True

>>> mem = Memory(256)
>>> for addr in range(0, 256):
...   mem[addr] = 101
>>> init_heap(mem, 16, 240)
>>> heap_ok(mem)
True


>>> nonheap,size = 256,2**12
>>> mem = Memory(size) ; init_heap(mem, nonheap, size-nonheap)
>>> while random_mutation(mem):
...     pass
>>> before = sorted((block_kind(mem, addr), block_size(mem, addr))
...                 for addr in trace_heap(mem))
>>> collect(mem)
>>> after = sorted((block_kind(mem, addr), block_size(mem, addr))
...                for addr in trace_heap(mem))
>>> print(True if before == after else show_heap(mem, scan_heap))
True
>>> heap_check(mem)


>>> nonheap,size = 256,2**12
>>> mem = Memory(size) ; init_heap(mem, nonheap, size-nonheap)
>>> while random_mutation(mem):
...     pass

>>> any(block_marked(mem, addr) for addr in trace_heap(mem))
False
>>> mark(mem)
>>> all(block_marked(mem, addr) for addr in trace_heap(mem))
True


>>> nonheap,size = 256,2**12
>>> mem = Memory(size) ; init_heap(mem, nonheap, size-nonheap)
>>> dead_block = allocate(mem, DATA_BLOCK, 100)
>>> heap_root = mem(24)[HEAP_ROOT]
>>> mem(24)[heap_root+1] = live_block = allocate(mem, DATA_BLOCK, 100)

>>> mark(mem)
>>> new_next = compute_forwards(mem)
>>> new_next == live_block - HEADER_SIZE
True
>>> block_forward(mem, heap_root) == heap_root
True
>>> block_forward(mem, live_block) == dead_block
True


>>> START, SIZE = 3*2**17, 2**19 ; mem = Memory(2**20)

>>> init_heap(mem, START, SIZE)
>>> heap_ok(mem)
True
>>> mem(24)[HEAP_NEXT] = 0
>>> heap_ok(mem)
False
>>> mem(24)[HEAP_NEXT] = 2**20-1
>>> heap_ok(mem)
False
>>> mem(24)[HEAP_NEXT] = mem(24)[HEAP_END]
>>> heap_ok(mem)
False
>>> 


>>> size = 2**10
>>> mem = Memory(size) ; init_heap(mem, 256, size-256)

>>> for _ in range(100):
...   _ = random_mutation(mem)
>>> heap_ok(mem)
True

>>> while random_mutation(mem):
...   pass
>>> heap_ok(mem)
True
