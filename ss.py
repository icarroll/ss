# TODO:
# change trace_heap to use pointer reversal

# MAYBE:
# bounds check init_heap
# check for block overlap in heap_check
# properly test heap_check
# properly test collect

from collections import deque
from io import StringIO
from random import choice, lognormvariate, random, randrange
import sys

class Error(Exception):
    pass

class HeapError(Error):
    pass

def Memory(size):
    class Memory:
        def __init__(self, memory, bits):
            self.memory = memory
            self.bits = bits

        def __setitem__(self, key, value):
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

        def __len__(self):
            return len(self.memory)

        def valid(self, addr):
            return 0 <= addr < len(self.memory) - 1 + self.bits // 8

        def copy(self):
            return Memory(bytearray(self.memory), self.bits)

    return Memory(bytearray(size), 8)

HEAP_NEXT = 0
HEAP_START = 3
HEAP_END = 6
HEAP_ROOT = 9
_INITIAL_ROOT_SIZE = 40
def init_heap(mem, start, size):
    if start + size > len(mem):
        raise HeapError("Heap size {0} exceeds memory size.".format(size))

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
HEADER_SIZE = 7
def allocate(mem, kind, size, gc=True):
    addr = mem(24)[HEAP_NEXT] + HEADER_SIZE

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

def block_pointers(mem, block_addr):   # generator
    size = block_size(mem, block_addr)
    for addr in range(block_addr, block_addr+size-size%4, 4):
        tag = mem[addr]
        if tag == 0:
            pointer = mem(24)[addr+1]
            if pointer:
                yield (addr, pointer)

def trace_heap(mem):   # generator
    root_addr = mem(24)[HEAP_ROOT]

    seen_addrs = set([root_addr])
    block_addrs = deque([root_addr])
    while block_addrs:
        block_addr = block_addrs.popleft()
        yield block_addr

        kind = block_kind(mem, block_addr)
        if kind is POINTER_BLOCK:
            for _, pointer in block_pointers(mem, block_addr):
                if pointer not in seen_addrs:
                    block_addrs.append(pointer)
                    seen_addrs.add(pointer)

def scan_heap(mem):   # generator
    heap_start = mem(24)[HEAP_START]
    heap_next = mem(24)[HEAP_NEXT]

    block_addr = heap_start + HEADER_SIZE
    while block_addr < heap_next:
        size = block_size(mem, block_addr)
        yield block_addr
        block_addr += HEADER_SIZE + size

def collect(mem):
    mark(mem)

    new_next = compute_forwards(mem)
    new_root = block_forward(mem, mem(24)[HEAP_ROOT])

    update_pointers(mem)

    compact(mem)
    mem(24)[HEAP_NEXT] = new_next
    mem(24)[HEAP_ROOT] = new_root

def mark(mem):
    for block_addr in trace_heap(mem):
        mark_block(mem, block_addr)

def compute_forwards(mem):
    next_free_addr = mem(24)[HEAP_START]
    for block_addr in scan_heap(mem):
        if block_marked(mem, block_addr):
            new_addr = next_free_addr + HEADER_SIZE
            set_block_forward(mem, block_addr, new_addr)
            next_free_addr = new_addr + block_size(mem, block_addr)

    return next_free_addr

def update_pointers(mem):
    for block_addr in scan_heap(mem):
        if not block_marked(mem, block_addr):
            continue
        kind = block_kind(mem, block_addr)
        if kind is POINTER_BLOCK:
            for addr, pointer in block_pointers(mem, block_addr):
                mem(24)[addr+1] = block_forward(mem, pointer)

def compact(mem):
    for old_addr in scan_heap(mem):
        if not block_marked(mem, old_addr):
            continue

        new_addr = block_forward(mem, old_addr)
        size = block_size(mem, old_addr)
        for ix in range(-HEADER_SIZE, size):
            mem[new_addr+ix] = mem[old_addr+ix]

        set_block_forward(mem, new_addr, 0)
        unmark_block(mem, new_addr)

def heap_ok(mem):
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

    for block_addr in trace_heap(mem):
        size = block_size(mem, block_addr)
        if not (mem(24)[HEAP_START] + HEADER_SIZE
                <= block_addr
                < mem(24)[HEAP_END] - size):
            raise HeapError("Block at {0} extends outside heap.".format(block_addr))
        if not (mem(24)[HEAP_START] + HEADER_SIZE
                <= block_addr
                <= mem(24)[HEAP_NEXT] - size):
            raise HeapError("Block at {0} extends outside live heap.".format(block_addr))

        kind = block_kind(mem, block_addr)
        if kind is DATA_BLOCK:
            continue
        if kind is not POINTER_BLOCK:
            raise HeapError("Block at {0} has invalid kind {1}.".format(block_addr, kind))

        for _, pointer in block_pointers(mem, block_addr):
            if not mem.valid(pointer):
                raise HeapError("Block at {0} offset {1} points outside memory.".format(block_addr, block_addr-addr))

def random_block(mem, only_pointer_blocks=False):
    if only_pointer_blocks:
        def is_pointer(addr):
            return block_kind(mem, addr) is POINTER_BLOCK

        block_addrs = filter(is_pointer, trace_heap(mem))
    else:
        block_addrs = trace_heap(mem)

    chosen = next(block_addrs)
    count = 1
    for block_addr in block_addrs:
        count += 1
        if random() < 1/count:
            chosen = block_addr

    return chosen

def random_mutation(mem):
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
    which = randrange(block, block+size-size%4, 4)
    mem[which] = 0
    mem(24)[which+1] = newptr

    return True

def show_heap(mem, traverse=scan_heap):
    msg = StringIO()

    heap_start = mem(24)[HEAP_START]
    heap_root = mem(24)[HEAP_ROOT]
    heap_next = mem(24)[HEAP_NEXT]
    heap_end = mem(24)[HEAP_END]
    print("start=0x{0:06x} root=0x{1:06x} next=0x{2:06x} end=0x{3:06x}"
          .format(heap_start, heap_root, heap_next, heap_end), file=msg)

    for block_addr in traverse(mem):
        forward = block_forward(mem, block_addr)
        flags = block_flags(mem, block_addr)
        kind = block_kind(mem, block_addr)
        marked = block_marked(mem, block_addr)
        size = block_size(mem, block_addr)

        fmt = ("0x{:06x}: forward=0x{:06x} flags=0x{:02x} (kind={!s:.1}"
               " marked={!s:.1}) size={}")
        print(fmt.format(block_addr, forward, flags, kind, marked, size),
              file=msg)

        if kind is POINTER_BLOCK:
            for addr, pointer in block_pointers(mem, block_addr):
                print("  {:8}: 0x{:06x}".format(addr-block_addr, pointer),
                      file=msg)

    return msg.getvalue()

def debug(type, value, tb):
    import traceback, pdb
    traceback.print_exception(type, value, tb)
    print()
    pdb.pm()

if __name__ == "__main__":
    if "-d" in sys.argv:
        sys.excepthook = debug

    if "-t" in sys.argv:
        import doctest
        fails,_ = doctest.testfile("tests.py")
        if not fails:
            print("OK")
    else:
        pass
