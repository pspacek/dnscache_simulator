import dns.rdatatype

import rfc2308

"""
Simulate RFC 4035 cache, resolver, and auth.

Cache exact match + negative caching.

Ignores NSEC magic because RFC 4035 section 4.5
is against synthtetising answers from NSEC.
"""

class Cache(rfc2308.Cache):
    pass

class Resolver(rfc2308.Resolver):
    pass

class Authoritative(rfc2308.Authoritative):
    def _gen_noerror(self, name, rrtype, ttl):
        rcode, answers = super()._gen_noerror(name, rrtype, ttl)
        if rrtype == dns.rdatatype.NS:
            # add DS if it exists
            node = self.rootzone[name]
            try:
                ds_rrs = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
                answers[(name, dns.rdatatype.DS)] = {"ttl": ds_rrs.ttl}
            except KeyError:
                pass
        return (rcode, answers)
