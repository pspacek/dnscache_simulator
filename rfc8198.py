import bisect

import dns.rdatatype

import rfc4035

"""
Simulate RFC 8198 cache, resolver, and auth.

Cache exact match + negative caching.

Auth now sends relevant NSECs
"""

class Cache(rfc4035.Cache):
    def __init__(self):
        super().__init__()
        self.ordering = []  # ordered list of owner names
        # self.storage is dict of owner name -> dict of values

    def get_name(self, name):
        raise NotImplementedError('use prove_name_nonexistence()')

    def put_name(self, name):
        raise NotImplementedError('RFC 8198 cache requires NSEC')

    def put_rrtype(self, name, rrtype, data):
        """
        cache information for one RR type
        """
        if rrtype == dns.rdatatype.NSEC:
            assert data.keys() == {'ttl', 'next', 'types'}
        else:
            assert data.keys() == {'ttl'}
        data['ttl'] += self.now

        if name not in self.storage:
            # add name into ordered sequence
            ridx = bisect.bisect_right(self.ordering, name)
            self.ordering.insert(ridx, name)

        self.storage.setdefault(name, {})[rrtype] = data

    def get_rrtype(self, name, rrtype):
        try:
            self._get_rrtype(name, rrtype)
            self.hit += 1
        except KeyError:
            self.miss += 1
            raise

    def _get_rrtype(self, name, rrtype):
        if name not in self.storage:
            return self.prove_name_nonexistence(name)

        node = self.storage[name]
        if rrtype in node:
            data = node[rrtype]
            if data['ttl'] < self.now:
                raise KeyError('expired')
                # we assume static data so we do not need to check NSECs
            else:
                return True

        # RR type not found at node, check NSEC
        assert rrtype != dns.rdatatype.NSEC
        nsec = node[dns.rdatatype.NSEC]
        if nsec['ttl'] < self.now:
            raise KeyError('NSEC expired')
        if rrtype in nsec['types']:
            raise KeyError('RR type not in cache but exists')
        else:
            return True  # non-existence was proven, do not query

    def prev_name(self, name):
        """
        Find name preceeding given name in DNSSEC canonical ordering.

        Raises: IndexError if such name is not present in cache.
        """
        assert name not in self.storage
        ridx = bisect.bisect_right(self.ordering, name)
        return self.ordering[ridx - 1]

    def prove_name_nonexistence(self, name):
        """
        Returns True if non-existence can be proved using data in cache.
        Raises KeyError if cache does not contain sufficient data.
        """
        try:
            pname = self.prev_name(name)
        except IndexError:
            raise KeyError('no predecesor found in cache')
        pnode = self.storage[pname]
        nsec = pnode[dns.rdatatype.NSEC]
        if nsec['ttl'] < self.now:
            raise KeyError('expired')
        if nsec['next'] > name:
            assert pname < name
            return True
        else:
            raise KeyError('covering NSEC not found')


class Resolver(rfc4035.Resolver):
    def __init__(self, auth):
        super().__init__(auth)
        self.cache = Cache()

    def lookup(self, name, rrtype):
        assert name.is_absolute()
        name = name.canonicalize()
        try:
            return self.cache.get_rrtype(name, rrtype)
        except KeyError:
            rcode, answers = self.auth.query(name, rrtype)
            self._store_answers(answers)

    def _store_answers(self, answers):
        for owner, data in answers.items():
            name, rrtype = owner
            assert 'ttl' in data
            if rrtype == dns.rdatatype.NSEC:
                assert 'next' in data
                assert 'types' in data
            self.cache.put_rrtype(name, rrtype, data)


class Authoritative(rfc4035.Authoritative):
    def __init__(self, rootdb):
        super().__init__(rootdb)
        self.nsecs = [name.canonicalize()
                      for name, node in self.rootzone.nodes.items()
                      if node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)]
        self.nsecs.sort()

    def _gen_nxdomain(self, name):
        """
        Generate answer containing NSEC from owner name "on the left"
        from given name.
        """
        ridx = bisect.bisect_right(self.nsecs, name)  # right next to wanted name
        lidx = ridx - 1  # this is easier than bisect_left + its corner cases
        lname = self.nsecs[lidx]  # name on the left from the wanted name
        lnode = self.rootzone[lname]
        lnsec_rrs = lnode.find_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)
        assert len(lnsec_rrs) == 1
        lnsec = lnsec_rrs[0]
        answers = {(lname, dns.rdatatype.NSEC):
                    {"ttl": self.neg_ttl,
                     "next": lnsec.next,
                     "types": _bitmap_to_set(lnsec.windows)}}
        return (dns.rcode.NXDOMAIN, answers)

    def _gen_nodata(self, name, rrtype):
        node = self.rootzone[name]
        nsec_rrs = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.NSEC)
        nsec = nsec_rrs[0]
        answers = {}
        answers[(name, dns.rdatatype.NSEC)] = {"ttl": self.neg_ttl,
                                               "next": nsec.next,
                                               "types": _bitmap_to_set(nsec.windows)}
        return (dns.rcode.NOERROR, answers)


    def _gen_noerror(self, name, rrtype, ttl):
        rcode, answers = super()._gen_noerror(name, rrtype, ttl)
        if rrtype == dns.rdatatype.NS:
            # add DS if it exists
            node = self.rootzone[name]
            try:
                ds_rrs = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
                answers[(name, dns.rdatatype.DS)] = {'ttl': ds_rrs.ttl}
            except KeyError:
                pass
        return (rcode, answers)


def _bitmap_to_set(bitmap_windows):
    """
    Convert dnspython's list of NSEC windows to set of RR type numbers.
    """
    types = set()
    for (window, bitmap) in bitmap_windows:
        bits = []
        for i in range(0, len(bitmap)):
            byte = bitmap[i]
            for j in range(0, 8):
                if byte & (0x80 >> j):
                    types.add(window * 256 + i * 8 + j)
    return types
