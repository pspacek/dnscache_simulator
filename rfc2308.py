"""
Simulate RFC 2308 cache, resolver, and auth.

Cache exact match + negative caching.
"""

from pprint import pformat
import time

import dns.resolver
import dns.zone


class Cache(object):
    def __init__(self):
        self.storage = {}
        self.hit = 0
        self.miss = 0

    def __str__(self):
        return pformat({'hit': self.hit, 'miss': self.miss})

    def put_name(self, name, ttl):
        """
        cache information for whole name
        """
        self.storage[name] = int(time.monotonic() + ttl)

    def get_name(self, name):
        """
        Returns:
        - a node dict if node is in cache
        - KeyError if node is not in cache (or is expired)
        - NXDOMAIN if non-existence of node is in cache and valid
        """
        node = self.storage[name]
        if isinstance(node, int):
            # NXDOMAIN, check if it is still valid
            expires = node
            if expires < time.monotonic():
                raise KeyError('expired')
            else:
                raise dns.resolver.NXDOMAIN()
        else:
            return node

    def put_rrtype(self, name, rrtype, ttl):
        """
        cache information for one RR type
        """
        assert (name not in self.storage) or (isinstance(self.storage[name], dict)), 'unsupported put operation'
        self.storage.setdefault(name, {})[rrtype] = int(time.monotonic() + ttl)

    def get_rrtype(self, name, rrtype):
        try:
            node = self.get_name(name)
            node[rrtype]  # verify RRtype is in cache
        except KeyError:  # not in cache
            self.miss += 1
            raise
        except dns.resolver.NXDOMAIN:  # cached NXDOMAIN
            pass
        self.hit += 1


class Resolver(object):
    def __init__(self, rootdb):
        self.cache = Cache()
        self.auth = Authoritative(rootdb)

    def lookup(self, name, rrtype):
        try:
            return self.cache.get_rrtype(name, rrtype)
        except KeyError:
            rcode, ttl = self.auth.query(name, rrtype)
            if rcode == dns.rcode.NOERROR:
                self.cache.put_rrtype(name, rrtype, ttl)
            else:
                self.cache.put_name(name, ttl)


class Authoritative(object):
    def __init__(self, rootdb):
        self.queries = 0
        self.rootzone = dns.zone.from_file(rootdb, origin=dns.name.root)

        rootnode = self.rootzone[dns.name.root]
        soa_rrs = rootnode.find_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        soa = soa_rrs[0]
        self.neg_ttl = min(soa_rrs.ttl, soa.minimum)  # https://tools.ietf.org/html/rfc2308#section-5

    def query(self, name, rrtype):
        """
        Returns: (rcode, ttl)
        """
        self.queries += 1
        try:
            node = self.rootzone[name]
        except KeyError:
            return (dns.rcode.NXDOMAIN, self.neg_ttl)
        try:
            rrs = node.find_rdataset(dns.rdataclass.IN, rrtype)
            return (dns.rcode.NOERROR, rrs.ttl)
        except KeyError:
            return (dns.rcode.NOERROR, self.neg_ttl)
