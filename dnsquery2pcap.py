#!/usr/bin/env python

import getopt
import os
import pcappy
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import sys

import utilsdns


def usage():
    print """
dnsquery2pcap.py [ OPTIONS ] [ tsv file... ]

Read packets from given files or stdin, parse them as tab separated
simplified DNS file and craft a pcap file with appropriate DNS
requests in stdout.

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

    dump = pcappy.PcapPyDead(snaplen=65536).dump_open(sys.stdout)
    hdr = {'ts':{'tv_sec':0, 'tv_usec':0}}

    ether = Ether(src="0", dst="0")
    ip = IP(ttl=255, src='0.0.0.0')

    counter = 1
    for fd in readfds:
        for line in fd:
            line = line.strip()
            if not line or line[0] in '#;':
                continue
            parts = line.split("\t")

            domain, qtype, qclass = (parts + ['A', 'INET'])[:3]
            qtype = int(qtype) if qtype.isdigit() else utilsdns.str2qtype[qtype.upper()]
            qclass = int(qclass) if qclass.isdigit() else utilsdns.str2qclass[qclass.upper()]

            domain = domain.rstrip('.')

            p = (ether/ip/
                 UDP(sport=counter % 65536, dport=53)/
                 DNS(id=counter % 65536,
                     qd=DNSQR(qname=domain,
                              qtype=qtype,
                              qclass=qclass)))
            raw = str(p)

            hdr['caplen'] = hdr['len'] = len(raw)
            dump.write(hdr, raw)
            counter += 1

    sys.stdout.flush()
    dump.flush()


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
