#!/usr/bin/env python

import getopt
import sys
import struct
import StringIO as stringio

import utils


def usage():
    print r"""
bpf_validate_dns.py [ OPTIONS ]

Generate raw BPF rules that match malformed DNS requests.

Options are:
  -h, --help         print this message
  -n, --negate       capture packets that don't match given domains
  -s, --assembly     print BPF assembly instead of byte code
  -o, --offset       offset of l3 (IP) header, 14 by default
  -6, --inet6        rule should match IPv6, not IPv4 packets
""".lstrip()
    sys.exit(2)

def main():
    negate = assembly = False
    l3_off = 14
    ipversion = 4

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hnso:6",
                                   ["help", "negate",
                                    "assembly", "offset=", "inet6"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-n", "--negate"):
            negate = True
        elif o in ("-s", "--assembly"):
            assembly = True
        elif o in ("-o", "--offset"):
            l3_off = int(a)
        elif o in ("-6", "--inet6"):
            ipversion = 6
        else:
            assert False, "unhandled option"

    if args:
        print >> sys.stderr, "No arguments accepted."
        sys.exit(-1)

    if not assembly:
        sys.stdout, saved_stdout = stringio.StringIO(), sys.stdout

    if ipversion == 4:
        print "    ld #%i" % (l3_off + 8) # 8B of udp
        print "    ldx 4*([%i]&0xf)" % (l3_off,)
        print "    add x"
    elif ipversion == 6:
        # assuming first "next header" is UDP
        print "    ld #%i" % (l3_off + 40 + 8) # 40B of ipv6 + 8B of udp

    print "    tax"
    print "    ; x = offset of first byte in DNS header"
    print
    print "    ldh [x + 4]        ; qdcount must be 1"
    print "    jneq #0x1, match"
    print "    ld [x + 6]         ; ancount and nscount must be 0"
    print "    jneq #0x0, match"
    print "    ldh [x + 10]       ; arcount must be 0 or 1"
    print "    jgt #0x1, match"
    print "    ret #%i" % (0 if not negate else 1)
    print
    print "match:"
    print "    ret #%i" % (1 if not negate else 0)

    sys.stdout.flush()

    if not assembly:
        assembly = sys.stdout.seek(0)
        assembly = sys.stdout.read()
        sys.stdout = saved_stdout
        print utils.bpf_compile(assembly)


if __name__ == "__main__":
    main()
