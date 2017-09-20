import os.path

import dns.rdatatype

from rfc4035 import Resolver, Authoritative


def test_res_nxdomain():
    """NXDOMAIN caching"""
    auth = Authoritative(os.path.join(os.path.dirname(__file__), 'test_root.zone.signed'))
    res = Resolver(auth)
    res.lookup('nonexistent.', 2)
    assert res.cache.miss == 1
    assert res.cache.hit == 0
    assert res.auth.queries == 1

    # time 0
    res.lookup('nonexistent.', 666)
    assert res.cache.miss == 1
    assert res.cache.hit == 1
    assert res.auth.queries == 1

    # time 5 < min(SOA TTL 10, MINIMUM)
    res.set_reltime(5)
    res.lookup('nonexistent.', 324)
    assert res.cache.miss == 1
    assert res.cache.hit == 2
    assert res.auth.queries == 1

    # time 11 > min(SOA TTL 10, MINIMUM)
    res.set_reltime(11)
    res.lookup('nonexistent.', 555)
    assert res.cache.miss == 2
    assert res.cache.hit == 2
    assert res.auth.queries == 2


def test_res_nodata():
    """NODATA caching"""
    auth = Authoritative(os.path.join(os.path.dirname(__file__), 'test_root.zone.signed'))
    res = Resolver(auth)
    res.lookup('.', 666)
    assert res.cache.miss == 1
    assert res.cache.hit == 0
    assert res.auth.queries == 1

    # time 1 < TTL 2
    res.set_reltime(1)
    res.lookup('.', 666)
    assert res.cache.miss == 1
    assert res.cache.hit == 1
    assert res.auth.queries == 1

    # query for different RR type must go through
    res.lookup('.', 2)
    assert res.cache.miss == 2
    assert res.cache.hit == 1
    assert res.auth.queries == 2

    # time 5 > TTL 2 + query time 2
    res.set_reltime(5)
    res.lookup('.', 2)
    assert res.cache.miss == 3
    assert res.cache.hit == 1
    assert res.auth.queries == 3

def test_res_noerror():
    """NOERROR caching"""
    auth = Authoritative(os.path.join(os.path.dirname(__file__), 'test_root.zone.signed'))
    res = Resolver(auth)

    res.lookup('test.', 2)
    assert res.cache.miss == 1
    assert res.cache.hit == 0
    assert res.auth.queries == 1

    # time 1 < TTL 2
    res.set_reltime(1)
    res.lookup('test.', dns.rdatatype.NS)
    assert res.cache.miss == 1
    assert res.cache.hit == 1
    assert res.auth.queries == 1

    # DS must be in cache - it was sent along with NS
    res.lookup('test.', dns.rdatatype.DS)
    assert res.cache.miss == 1
    assert res.cache.hit == 2
    assert res.auth.queries == 1


    # time 3 > TTL 2
    res.set_reltime(3)
    res.lookup('test.', dns.rdatatype.DS)
    assert res.cache.miss == 2
    assert res.cache.hit == 2
    assert res.auth.queries == 2

    # NS must be expired as well
    res.lookup('test.', dns.rdatatype.NS)
    assert res.cache.miss == 3
    assert res.cache.hit == 2
    assert res.auth.queries == 3
