import os.path

from rfc2308 import Resolver


def test_nxdomain():
    """NXDOMAIN caching"""
    res = Resolver(os.path.join(os.path.dirname(__file__), 'test_root.zone'))
    res.lookup('nonexistent.', 2)
    assert res.cache.miss == 1
    assert res.cache.hit == 0

    res.lookup('nonexistent.', 666)
    assert res.cache.miss == 1
    assert res.cache.hit == 1


def test_nodata():
    """NODATA caching"""
    res = Resolver(os.path.join(os.path.dirname(__file__), 'test_root.zone'))
    res.lookup('.', 666)
    assert res.cache.miss == 1
    assert res.cache.hit == 0

    res.lookup('.', 666)
    assert res.cache.miss == 1
    assert res.cache.hit == 1

    # query for different RR type must go through
    res.lookup('.', 2)
    assert res.cache.miss == 2
    assert res.cache.hit == 1


def test_noerror():
    """NOERROR caching"""
    res = Resolver(os.path.join(os.path.dirname(__file__), 'test_root.zone'))
    res.lookup('.', 2)
    assert res.cache.miss == 1
    assert res.cache.hit == 0

    res.lookup('.', 2)
    assert res.cache.miss == 1
    assert res.cache.hit == 1
