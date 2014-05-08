#!/usr/bin/env python

import getopt
import os
import sys
import struct
import pcappy

import utils
import utilsdns


def usage():
    print """
pcap2dnsquery.py [ OPTIONS ] [ pcap file... ]

Read packets from given pcap files or stdin, parse them as DNS and
print in a simplified readable form to stdout.

Options are:
  -h, --help         print this message
""".lstrip()
    sys.exit(2)


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        else:
            assert False, "unhandled option"

    if not args:
        readfds = [sys.stdin]
    else:
        readfds = [open(fname, 'rb') for fname in args]

    l3_off = None

    ignoredcount = 0
    for fd in readfds:
        p = pcappy.open_offline(fd)

        while True:
            try:
                r = p.next_ex()
            except pcappy.PcapPyException:
                break
            if r is None:
                break
            hdr, data = r

            if l3_off is None:
                l3_off = utils.find_ip_offset(data)

            l5_off = find_dns_offset(data, l3_off)
            if l5_off is None:
                ignoredcount += 1
                continue
            dns_id, flags, qdcnt, anscnt, authcnt, extracnt = \
                struct.unpack_from('!HHHHHH', data, l5_off)
            if  (flags | 0x10) != 0x10 or qdcnt != 1 or anscnt != 0 or authcnt != 0 or extracnt not in (0,1):
                ignoredcount += 1
                continue
            domain, qtype, qclass = utilsdns.unpack_domain(data, l5_off + 12)
            print '%s.\t%s\t%s' % (domain,
                                  utilsdns.qtype2str.get(qtype, qtype),
                                  utilsdns.qclass2str.get(qclass, qclass))

    ignoredcount += 1
    print >>sys.stderr, "invalid: %i" % (ignoredcount,)


def find_dns_offset(data, off):
    ipv, = struct.unpack_from('!B', data, off)
    if ipv & 0xF0 == 0x40:
        hdrlen = (ipv&0x0F) * 4
        _, _, total_length, ip_id, _, ttl, proto, _ = \
            struct.unpack_from('!BBHHHBBH', data, off)
        if proto != 17:
            return None
        off += hdrlen
    elif ipv & 0xF0 == 0x60:
        _, payload_length, next_header, ttl = \
            struct.unpack_from('!IHBB', data, off)
        if next_header != 17:
            return None
        off += 40
        # no support for chained headers
    else:
        return None

    return off + 8


if __name__ == "__main__":
    try:
        main()
    except IOError, e:
        if e.errno == 32:
            os._exit(-1)
        raise
    except KeyboardInterrupt:
        os._exit(-1)

    # normal exit crashes due to a double free error in pcappy
    os._exit(0)
