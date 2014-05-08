import struct


_dns_type = map(lambda (a,b): (a, int(b)), map(lambda line: line.split(), '''
A          1
NS         2
MD         3
MF         4
CNAME      5
SOA        6
MB         7
MG         8
MR         9
NULL       10
WKS        11
PTR        12
HINFO      13
MINFO      14
MX         15
TXT        16
RP         17
AFSDB      18
X25        19
ISDN       20
RT         21
NSAP       22
NSAPPTR    23
SIG        24
KEY        25
PX         26
GPOS       27
AAAA       28
LOC        29
NXT        30
EID        31
NIMLOC     32
SRV        33
ATMA       34
NAPTR      35
KX         36
CERT       37
DNAME      39
OPT        41
DS         43
SSHFP      44
IPSECKEY   45
RRSIG      46
NSEC       47
DNSKEY     48
DHCID      49
NSEC3      50
NSEC3PARAM 51
TLSA       52
HIP        55
NINFO      56
RKEY       57
TALINK     58
CDS        59
SPF        99
UINFO      100
UID        101
GID        102
UNSPEC     103
NID        104
L32        105
L64        106
LP         107
EUI48      108
EUI64      109
TKEY       249
TSIG       250
IXFR       251
AXFR       252
MAILB      253
MAILA      254
ANY        255
URI        256
CAA        257
TA         32768
DLV        32769
'''.strip().split('\n')))

qtype2str = dict( (v, n) for n, v in _dns_type)
str2qtype = dict( (n, v) for n, v in _dns_type)

_dns_class = map(lambda (a,b): (a, int(b)), map(lambda line: line.split(), '''
INET   1
CSNET  2
CHAOS  3
HESIOD 4
NONE   254
ANY    255
'''.strip().split('\n')))

qclass2str = dict( (v, n) for n, v in _dns_class)
str2qclass = dict( (n, v) for n, v in _dns_class)


def unpack_domain(data, off):
    off1 = None

    parts = []
    while True:
        c, = struct.unpack_from('!B', data, off)
        if c == 0x00:
            off += 1
            break
        elif (c & 0xC0):
            c, = struct.unpack_from('!H', data, off)
            ptr = c ^ 0xc000
            off += 2
            if off1 == None:
                off1 = off
            off = ptr
        else:
            parts.append( data[off+1:off+1+c] )
            off += c + 1

    qtype, qclass = struct.unpack_from('!HH', data, off)
    return '.'.join(parts), qtype, qclass
