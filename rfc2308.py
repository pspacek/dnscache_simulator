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
        self.start = int(time.monotonic())
        self.now = self.start

    def __str__(self):
        return pformat({'hit': self.hit, 'miss': self.miss})

    def set_reltime(self, reltime):
        """
        move relative time
        """
        self.now = self.start + reltime

    def put_name(self, name, ttl):
        """
        cache information for whole name
        """
        self.storage[name] = self.now + ttl

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
            if expires < self.now:
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
        self.storage.setdefault(name, {})[rrtype] = self.now + ttl

    def get_rrtype(self, name, rrtype):
        try:
            node = self.get_name(name)
            expires = node[rrtype]  # verify RRtype is in cache
            if expires < self.now:
                raise KeyError('expired')
        except KeyError:  # not in cache
            self.miss += 1
            raise
        except dns.resolver.NXDOMAIN:  # cached NXDOMAIN
            pass
        self.hit += 1


class Resolver(object):
    def __init__(self, auth):
        self.cache = Cache()
        self.auth = auth

    def set_reltime(self, reltime):
        self.cache.set_reltime(reltime)

    def lookup(self, name, rrtype):
        try:
            return self.cache.get_rrtype(name, rrtype)
        except KeyError:
            rcode, answers = self.auth.query(name, rrtype)
            if rcode == dns.rcode.NOERROR:
                self._store_noerror(answers)
            else:
                assert rcode == dns.rcode.NXDOMAIN
                self._store_nxdomain(answers)

    def _store_noerror(self, answers):
        for owner, data in answers.items():
            name, rrtype = owner
            self.cache.put_rrtype(name, rrtype, data["ttl"])

    def _store_nxdomain(self, answers):
        # answers is just negative TTL
        assert len(answers) == 1
        for owner, data in answers.items():
            pass
        name, rrtype = owner
        assert rrtype == dns.rdatatype.ANY
        self.cache.put_name(name, data["ttl"])


class Authoritative(object):
    def __init__(self, rootdb):
        self.queries = 0
        self.rootzone = dns.zone.from_file(rootdb, origin=dns.name.root)

        rootnode = self.rootzone[dns.name.root]
        soa_rrs = rootnode.find_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        soa = soa_rrs[0]
        self.neg_ttl = min(soa_rrs.ttl, soa.minimum)  # https://tools.ietf.org/html/rfc2308#section-5

    def _gen_nxdomain(self, name):
        """
        (qname, type ANY) is used encode negative TTL for the resolver
        """
        answer = {(name, dns.rdatatype.ANY): {"ttl": self.neg_ttl}}
        return (dns.rcode.NXDOMAIN, answer)

    def _gen_nodata(self, name, rrtype):
        answers = {(name, rrtype): {"ttl": self.neg_ttl}}
        return (dns.rcode.NOERROR, answers)

    def _gen_noerror(self, name, rrtype, ttl):
        answers = {(name, rrtype): {"ttl": ttl}}
        return (dns.rcode.NOERROR, answers)

    def query(self, name, rrtype):
        """
        Returns: (rcode, {(name, rrtype): ttl})

        NXDOMAIN == rrtype ANY + TTL
        """
        self.queries += 1
        try:
            node = self.rootzone[name]
        except KeyError:  # NXDOMAIN
            return self._gen_nxdomain(name)
        try:
            rrs = node.find_rdataset(dns.rdataclass.IN, rrtype)
        except KeyError:  # NODATA
            return self._gen_nodata(name, rrtype)

        # NOERROR
        return self._gen_noerror(name, rrtype, rrs.ttl)
