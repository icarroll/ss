from hypothesis import assume, example, given
import hypothesis.strategies as st

import ss

'''
@given(size=st.integers(min_value=0, max_value=2**24),
       ix=st.integers(min_value=0),
       n=st.integers(min_value=0, max_value=2**8-1))
def test_memory_basic(size, ix, n):
    assume(ix < size)
    mem = ss.Memory(size)
    mem[ix] = n
    assert mem[ix] == n

@given(size=st.integers(min_value=0, max_value=2**24),
       nbytes=st.integers(min_value=1, max_value=4),
       ix=st.integers(min_value=0),
       n=st.integers(min_value=0))
def test_memory_width(size, nbytes, ix, n):
    assume(ix <= size-nbytes)
    assume(n < 2**(nbytes*8))
    mem = ss.Memory(size)
    width = nbytes * 8
    mem(width)[ix] = n
    assert mem(width)[ix] == n
    for read_bytes in range(1, nbytes+1):
        read_width = read_bytes * 8
        assert mem(read_width)[ix] == n % 2**read_width

@given(size=st.integers(min_value=0, max_value=2**24),
       nonheap=st.integers(min_value=16),
       heap=st.integers(min_value=64))
def test_init_heap(size, nonheap, heap):
    assume(size > nonheap + heap)
    mem = ss.Memory(size)
    ss.init_heap(mem, nonheap, heap)
    assert mem(24)[ss.HEAP_START] == nonheap
    assert mem(24)[ss.HEAP_END] == nonheap + heap
    ss.heap_check(mem)
'''

