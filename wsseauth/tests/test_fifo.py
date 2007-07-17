from wsseauth.fifo import Fifo

def test_fifo():
    fifo = Fifo()

    assert fifo.empty()
    fifo.append('morx')
    assert not fifo.empty()
    assert fifo.top() == 'morx'
    assert fifo.pop() == 'morx'

    assert fifo.empty()

    #---

    fifo.append('foo')
    fifo.append('bar')

    assert fifo.top() == 'foo'
    assert fifo.pop() == 'foo'
    assert not fifo.empty()
    assert fifo.pop() == 'bar'
    assert fifo.empty()

    #---

    fifo.append('foo')
    fifo.append('bar')

    assert fifo.top() == 'foo'
    assert fifo.pop() == 'foo'
    assert not fifo.empty()

    fifo.append('baz')

    assert fifo.pop() == 'bar'
    assert not fifo.empty()
    assert fifo.pop() == 'baz'
    assert fifo.empty()
