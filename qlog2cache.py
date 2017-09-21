#!/usr/bin/python3

from datetime import datetime
import io
import re
import sys

import dns.rdatatype

import rfc8198 as rfc

logregex = r'^([0-9T:.-]+)\+[0-9]{2}:[0-9]{2} \'([^.]*\.)\' type \'([^\']+)\''

def read_queries(infile):
# 2017-09-08T15:42:22.186207+02:00 'prod-t.singular.net.' type 'A'
# find TLDs and root, ignore TZ (assume it is always the same in one log)
    lineno = 0
    start = None
    try:
        for line in infile:
            lineno += 1
            match = re.match(logregex, line)
            if not match:
                continue

            now = datetime.strptime(match.group(1), '%Y-%m-%dT%H:%M:%S.%f')
            if not start:
                start = now
            reltime = int((now - start).total_seconds())
            assert reltime >= 0, 'cannot go back %s seconds in time: line "%s"' % (reltime, line)

            qname = match.group(2).encode('ascii')  # dnspython would try to decode it as unicode string
            rrtype = dns.rdatatype.from_text(match.group(3))

            #print('{} {} {}'.format(reltime, qname, rrtype))
            yield (reltime, dns.name.from_text(bytes(qname)), rrtype)
    except:
        print('failed line no. {}'.format(lineno))
        raise

auth = rfc.Authoritative('root.zone')
res = rfc.Resolver(auth)

intext = io.TextIOWrapper(sys.stdin.buffer, encoding='ascii')
prevtime = 0
print('time,hit,miss')
for now, qname, rrtype in read_queries(intext):
    res.set_reltime(now)
    res.lookup(qname, rrtype)

    if now - prevtime >= 3600:
        prevtime = int(now / 3600) * 3600
        print('{},{},{}'.format(now, res.cache.hit, res.cache.miss))
