import os.path

import dns.name
import dns.rdatatype

from rfc8198 import Resolver, Authoritative

def N(name_str):
    return dns.name.from_text(name_str)

def test_res_nxdomain():
    """NXDOMAIN caching"""
    auth = Authoritative(os.path.join(os.path.dirname(__file__), 'test_root.zone.signed'))
    res = Resolver(auth)
    res.lookup(N('nonexistent.'), 2)
    assert res.cache.miss == 1
    assert res.cache.hit == 0
    assert res.auth.queries == 1

    # time 0
    res.lookup(N('nonexistent.'), 666)
    assert res.cache.miss == 1
    assert res.cache.hit == 1
    assert res.auth.queries == 1

    # time 0: nonexistent2 is covered by NSEC . -> test.
    res.lookup(N('nonexistent2.'), 666)
    assert res.cache.miss == 1
    assert res.cache.hit == 2
    assert res.auth.queries == 1

    # time 5 < min(SOA TTL 10, MINIMUM)
    res.set_reltime(5)
    res.lookup(N('nonexistent3.'), 324)
    assert res.cache.miss == 1
    assert res.cache.hit == 3
    assert res.auth.queries == 1

    # time 11 > min(SOA TTL 10, MINIMUM)
    res.set_reltime(11)
    res.lookup(N('nonexistent4.'), 555)
    assert res.cache.miss == 2
    assert res.cache.hit == 3
    assert res.auth.queries == 2

    # zzz. is outside of NSEC range . -> test., do query!
    res.lookup(N('zzz.'), 555)
    assert res.cache.miss == 3
    assert res.cache.hit == 3
    assert res.auth.queries == 3


def test_res_nodata():
    """NODATA caching"""
    auth = Authoritative(os.path.join(os.path.dirname(__file__), 'test_root.zone.signed'))
    res = Resolver(auth)
    res.lookup(N('.'), 666)
    assert res.cache.miss == 1
    assert res.cache.hit == 0
    assert res.auth.queries == 1

    # time 1 < TTL 2
    res.set_reltime(1)
    res.lookup(N('.'), 666)
    assert res.cache.miss == 1
    assert res.cache.hit == 1
    assert res.auth.queries == 1

    # first query for non-existent RR type must go through and grab NSEC
    res.lookup(N('.'), 2)
    assert res.cache.miss == 2
    assert res.cache.hit == 1
    assert res.auth.queries == 2

    # second query for non-existent RR type must use the cached NSEC
    res.lookup(N('.'), 2)
    assert res.cache.miss == 2
    assert res.cache.hit == 2
    assert res.auth.queries == 2

    # third query for yet-another non-existent RR type must use the cached NSEC
    res.lookup(N('.'), 111)
    assert res.cache.miss == 2
    assert res.cache.hit == 3
    assert res.auth.queries == 2

    # time 5 > TTL 2 + query time 1
    res.set_reltime(5)
    res.lookup(N('.'), 2)
    assert res.cache.miss == 3
    assert res.cache.hit == 3
    assert res.auth.queries == 3

    res.lookup(N('.'), 2)
    assert res.cache.miss == 3
    assert res.cache.hit == 4
    assert res.auth.queries == 3


def test_res_noerror():
    """NOERROR caching"""
    auth = Authoritative(os.path.join(os.path.dirname(__file__), 'test_root.zone.signed'))
    res = Resolver(auth)

    res.lookup(N('test.'), 2)
    assert res.cache.miss == 1
    assert res.cache.hit == 0
    assert res.auth.queries == 1

    # time 1 < TTL 2
    res.set_reltime(1)
    res.lookup(N('test.'), dns.rdatatype.NS)
    assert res.cache.miss == 1
    assert res.cache.hit == 1
    assert res.auth.queries == 1

    # DS must be in cache - it was sent along with NS
    res.lookup(N('test.'), dns.rdatatype.DS)
    assert res.cache.miss == 1
    assert res.cache.hit == 2
    assert res.auth.queries == 1

    # time 3 > TTL 2
    res.set_reltime(3)
    res.lookup(N('test.'), dns.rdatatype.DS)
    assert res.cache.miss == 2
    assert res.cache.hit == 2
    assert res.auth.queries == 2

    # NS must be expired as well
    res.lookup(N('test.'), dns.rdatatype.NS)
    assert res.cache.miss == 3
    assert res.cache.hit == 2
    assert res.auth.queries == 3
