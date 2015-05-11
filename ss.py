# TODO:
# change traverse_heap to use pointer reversal

# MAYBE:
# bounds check init_heap
# check for block overlap in heap_check
# properly test heap_check
# properly test collect

from collections import deque
from random import choice, lognormvariate, random, randrange
import sys

class Error(Exception):
    pass

class HeapError(Error):
    pass

def Memory(size):
    """
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
    """
    class Memory:
        def __init__(self, memory, bits):
            self.memory = memory
            self.bits = bits

        def __setitem__(self, key, value):
            log(2, "{0}: 0x{1:06x} <- 0x{2:0{3}x}".format(self.bits, key, value, self.bits//4))
            nbytes = self.bits // 8
            for ix in range(nbytes):
                self.memory[key+ix] = value % 256
                value //= 256

        def __getitem__(self, key):
            nbytes = self.bits // 8
            value = 0
            while nbytes:
                nbytes -= 1
                value *= 256
                value += self.memory[key+nbytes]

            return value

        def __call__(self, bits):
            if bits == self.bits:
                return self
            else:
                return Memory(self.memory, bits)

        def valid(self, addr):
            return 0 <= addr < len(self.memory) - 1 + self.bits // 8

    return Memory(bytearray(size), 8)

HEAP_NEXT = 0
HEAP_START = 3
HEAP_END = 6
HEAP_ROOT = 9
_INITIAL_ROOT_SIZE = 40
def init_heap(mem, start, size):
    """
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
    """
    mem(24)[HEAP_NEXT] = start
    mem(24)[HEAP_START] = start
    mem(24)[HEAP_END] = start + size
    mem(24)[HEAP_ROOT] = allocate(mem, POINTER_BLOCK, _INITIAL_ROOT_SIZE)

class Kind:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return self.name

    def __lt__(self, other):
        return id(self) < id(other)

POINTER_BLOCK = Kind("POINTER_BLOCK")
DATA_BLOCK = Kind("DATA_BLOCK")
_HEADER_SIZE = 7
def allocate(mem, kind, size, gc=True):
    """
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
    """
    addr = mem(24)[HEAP_NEXT] + _HEADER_SIZE

    new_next = addr + size
    if new_next >= mem(24)[HEAP_END]:
        if gc:
            collect(mem)
            return allocate(mem, kind, size, gc=False)
        else:
            return 0

    mem(24)[HEAP_NEXT] = new_next

    set_block_forward(mem, addr, 0)
    clear_block_flags(mem, addr)
    set_block_kind(mem, addr, kind)
    set_block_size(mem, addr, size)

    for ix in range(addr, new_next):
        mem[ix] = 0

    return addr

def block_forward(mem, addr):
    return mem(24)[addr-7]

def set_block_forward(mem, addr, forward):
    mem(24)[addr-7] = forward

def block_flags(mem, addr):
    return mem[addr-4]

def clear_block_flags(mem, addr):
    mem[addr-4] = 0

KIND_BIT = 0b00000001
def block_kind(mem, addr):
    return POINTER_BLOCK if mem[addr-4] & KIND_BIT else DATA_BLOCK

def set_block_kind(mem, addr, kind):
    if kind is POINTER_BLOCK:
        mem[addr-4] |= KIND_BIT
    else:
        mem[addr-4] &= ~KIND_BIT

MARK_BIT = 0b00000010
def block_marked(mem, addr):
    return bool(mem[addr-4] & MARK_BIT)

def mark_block(mem, addr):
    mem[addr-4] |= MARK_BIT

def unmark_block(mem, addr):
    mem[addr-4] &= ~MARK_BIT

def block_size(mem, addr):
    return mem(24)[addr-3]

def set_block_size(mem, addr, size):
    mem(24)[addr-3] = size

def traverse_heap(mem):   # generator
    root_addr = mem(24)[HEAP_ROOT]

    seen_addrs = set([root_addr])
    block_addrs = deque([root_addr])
    while block_addrs:
        block_addr = block_addrs.popleft()
        yield block_addr

        kind = block_kind(mem, block_addr)
        if kind is POINTER_BLOCK:
            size = block_size(mem, block_addr)
            for addr in range(block_addr, block_addr+size-size%4, 4):
                new_block_tag = mem[addr]
                if new_block_tag == 0:
                    new_block_addr = mem(24)[addr+1]
                    if new_block_addr == 0:
                        continue
                    if new_block_addr not in seen_addrs:
                        block_addrs.append(new_block_addr)
                        seen_addrs.add(new_block_addr)

def collect(mem):
    """
    >>> nonheap,size = 256,2**12
    >>> mem = Memory(size) ; init_heap(mem, nonheap, size-nonheap)
    >>> while random_mutation(mem):
    ...     pass
    >>> before = sorted((block_kind(mem, addr), block_size(mem, addr))
    ...                 for addr in traverse_heap(mem))
    >>> collect(mem)
    >>> after = sorted((block_kind(mem, addr), block_size(mem, addr))
    ...                for addr in traverse_heap(mem))
    >>> before == after
    True
    >>> heap_check(mem)
    """
    mark(mem)

    new_next = compute_forwards(mem)
    mem(24)[HEAP_ROOT] = block_forward(mem, mem(24)[HEAP_ROOT])

    update_pointers(mem)

    compact(mem)
    mem(24)[HEAP_NEXT] = new_next

def mark(mem):
    """
    >>> nonheap,size = 256,2**12
    >>> mem = Memory(size) ; init_heap(mem, nonheap, size-nonheap)
    >>> while random_mutation(mem):
    ...     pass

    >>> any(block_marked(mem, addr) for addr in traverse_heap(mem))
    False
    >>> mark(mem)
    >>> all(block_marked(mem, addr) for addr in traverse_heap(mem))
    True
    """
    for block_addr in traverse_heap(mem):
        mark_block(mem, block_addr)
        log(1, "marked", block_addr)

def compute_forwards(mem):
    """
    >>> nonheap,size = 256,2**12
    >>> mem = Memory(size) ; init_heap(mem, nonheap, size-nonheap)
    >>> dead_block = allocate(mem, DATA_BLOCK, 100)
    >>> heap_root = mem(24)[HEAP_ROOT]
    >>> mem(24)[heap_root+1] = live_block = allocate(mem, DATA_BLOCK, 100)

    >>> mark(mem)
    >>> new_next = compute_forwards(mem)
    >>> new_next == live_block - _HEADER_SIZE
    True
    >>> block_forward(mem, heap_root) == heap_root
    True
    >>> block_forward(mem, live_block) == dead_block
    True
    """
    heap_next = mem(24)[HEAP_NEXT]
    free_addr = mem(24)[HEAP_START]
    block_addr = mem(24)[HEAP_START] + _HEADER_SIZE
    while block_addr < heap_next:
        log(1, "computing forward", block_addr)
        increment = _HEADER_SIZE + block_size(mem, block_addr)
        if block_marked(mem, block_addr):
            set_block_forward(mem, block_addr, free_addr+_HEADER_SIZE)
            log(1, "forward", block_addr, free_addr+_HEADER_SIZE)
            free_addr += increment
        block_addr += increment

    log(1, "new next", free_addr)
    return free_addr

def update_pointers(mem):
    for block_addr in traverse_heap(mem):
        log(1, "updating pointers", block_addr)
        kind = block_kind(mem, block_addr)
        if kind is POINTER_BLOCK:
            size = block_size(mem, block_addr)
            for addr in range(block_addr, block_addr+size-size%4, 4):
                tag = mem[addr]
                if tag == 0:
                    pointer = mem(24)[addr+1]
                    if pointer:
                        mem(24)[addr+1] = block_forward(mem, pointer)
                        log(1, "update", block_addr, addr, pointer)

def compact(mem):
    for block_addr in sorted(traverse_heap(mem)):
        forward = block_forward(mem, block_addr)
        for ix in range(-_HEADER_SIZE, block_size(mem, block_addr)):
            mem[forward+ix] = mem[block_addr+ix]
        log(1, "compact", block_addr, forward)

        set_block_forward(mem, forward, 0)
        log(1, "zero forward", forward)
        unmark_block(mem, forward)
        log(1, "unmark", forward)

def heap_ok(mem):
    """
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
    """
    try:
        heap_check(mem)
        return True
    except HeapError:
        return False

def heap_check(mem):
    if not mem(24)[HEAP_START] <= mem(24)[HEAP_NEXT] < mem(24)[HEAP_END]:
        raise HeapError("Heap next address {0} outside of heap".format(mem(24)[HEAP_NEXT]))

    root_addr = mem(24)[HEAP_ROOT]
    if not mem.valid(root_addr):
        raise HeapError("Heap root address {0} outside of memory.".format(root_addr))
    if not mem(24)[HEAP_START] <= root_addr < mem(24)[HEAP_NEXT]:
        raise HeapError("Heap root address {0} outside of live heap".format(root_addr))
    if not mem(24)[HEAP_START] <= root_addr < mem(24)[HEAP_END]:
        raise HeapError("Heap root address {0} outside of heap".format(root_addr))

    for block_addr in traverse_heap(mem):
        size = block_size(mem, block_addr)
        if not (mem(24)[HEAP_START] + _HEADER_SIZE
                <= block_addr
                < mem(24)[HEAP_END] - size):
            raise HeapError("Block at {0} extends outside heap.".format(block_addr))
        if not (mem(24)[HEAP_START] + _HEADER_SIZE
                <= block_addr
                <= mem(24)[HEAP_NEXT] - size):
            raise HeapError("Block at {0} extends outside live heap.".format(block_addr))

        kind = block_kind(mem, block_addr)
        if kind is DATA_BLOCK:
            continue
        if kind is not POINTER_BLOCK:
            raise HeapError("Block at {0} has invalid kind {1}.".format(block_addr, kind))

        for addr in range(block_addr, block_addr+size-size%4, 4):
            new_block_tag = mem[addr]
            if new_block_tag == 0:
                new_block_addr = mem(24)[addr+1]
                if new_block_addr == 0:
                    continue
                if not mem.valid(new_block_addr):
                    raise HeapError("Block at {0} offset {1} points outside memory.".format(block_addr, block_addr-addr))

def random_block(mem, only_pointer_blocks=False):
    if only_pointer_blocks:
        def is_pointer(addr):
            return block_kind(mem, addr) is POINTER_BLOCK

        block_addrs = filter(is_pointer, traverse_heap(mem))
    else:
        block_addrs = traverse_heap(mem)

    chosen = next(block_addrs)
    count = 1
    for block_addr in block_addrs:
        count += 1
        if random() < 1/count:
            chosen = block_addr

    return chosen

def random_mutation(mem):
    """
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
    """
    action = randrange(3)
    if action == 0:
        newptr = 0
    elif action == 1:
        kind = choice([POINTER_BLOCK, DATA_BLOCK])
        newsize = 4 + int(100 * lognormvariate(0, 1))
        newptr = allocate(mem, kind, newsize, gc=False)
        if newptr == 0:
            return False
    elif action == 2:
        newptr = random_block(mem)

    block = random_block(mem, only_pointer_blocks=True)
    size = block_size(mem, block)
    ptr = randrange(block, block+size-size%4, 4)
    mem[ptr] = 0
    mem(24)[ptr+1] = newptr

    return True

def show_all_heap(mem):
    heap_start = mem(24)[HEAP_START]
    heap_root = mem(24)[HEAP_ROOT]
    heap_next = mem(24)[HEAP_NEXT]
    heap_end = mem(24)[HEAP_END]
    print("start=0x{0:06x} root=0x{1:06x} next=0x{2:06x} end=0x{3:06x}"
          .format(heap_start, heap_root, heap_next, heap_end))

    block_addr = heap_start + _HEADER_SIZE
    while block_addr < heap_next:
        forward = block_forward(mem, block_addr)
        flags = block_flags(mem, block_addr)
        kind = block_kind(mem, block_addr)
        marked = block_marked(mem, block_addr)
        size = block_size(mem, block_addr)

        fmt = ("0x{:06x}: forward=0x{:06x} flags=0x{:02x} (kind={!s:.1}"
               " marked={!s:.1}) size=0x{:06x}")
        print(fmt.format(block_addr, forward, flags, kind, marked, size))

        if kind is POINTER_BLOCK:
            for addr in range(block_addr, block_addr+size-size%4, 4):
                new_block_tag = mem[addr]
                if new_block_tag == 0:
                    new_block_addr = mem(24)[addr+1]
                    if new_block_addr == 0:
                        continue
                    print("    {:06x}".format(new_block_addr))

        block_addr += _HEADER_SIZE + size

def show_live_heap(mem):
    heap_start = mem(24)[HEAP_START]
    heap_root = mem(24)[HEAP_ROOT]
    heap_next = mem(24)[HEAP_NEXT]
    heap_end = mem(24)[HEAP_END]
    print("start=0x{0:06x} root=0x{1:06x} next=0x{2:06x} end=0x{3:06x}"
          .format(heap_start, heap_root, heap_next, heap_end))

    for block_addr in traverse_heap(mem):
        forward = block_forward(mem, block_addr)
        flags = block_flags(mem, block_addr)
        kind = block_kind(mem, block_addr)
        marked = block_marked(mem, block_addr)
        size = block_size(mem, block_addr)

        fmt = ("0x{:06x}: forward=0x{:06x} flags=0x{:02x} (kind={!s:.1}"
               " marked={!s:.1}) size=0x{:06x}")
        print(fmt.format(block_addr, forward, flags, kind, marked, size))

        if kind is POINTER_BLOCK:
            for addr in range(block_addr, block_addr+size-size%4, 4):
                new_block_tag = mem[addr]
                if new_block_tag == 0:
                    new_block_addr = mem(24)[addr+1]
                    if new_block_addr == 0:
                        continue
                    print("    {:06x}".format(new_block_addr))

def log(level, msg, *args):
    if LOG >= level:
        print(msg, *("{:06x}".format(arg) for arg in args))

def debug(type, value, tb):
    import traceback, pdb
    traceback.print_exception(type, value, tb)
    print()
    pdb.pm()

def frob():
    mem = Memory(2**12)
    init_heap(mem, 256, 2**12-256)

    show_all_heap(mem)
    print()

    collect(mem)
    show_all_heap(mem)

if __name__ == "__main__":
    if "-d" in sys.argv:
        sys.excepthook = debug

    global LOG
    if "-l" in sys.argv:
        LOG = 1
    elif "-ll" in sys.argv:
        LOG = 2
    else:
        LOG = 0

    if "-t" in sys.argv:
        import doctest
        fails,_ = doctest.testmod()
        if not fails:
            print("OK")
    else:
        frob()
