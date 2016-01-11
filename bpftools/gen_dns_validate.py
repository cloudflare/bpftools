import argparse
import string
import sys


def gen(args, l3_off=0, ipversion=4, negate=False):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        prog="%s dns_validate --" % (sys.argv[0]),
        description=r'''

Generate raw BPF rules that match malformed DNS requests. This
generator does not inspect the packet query name (queried domain), but
instead looks at general packet sanity. To be more precise it checks:

 - if the qdcount is exactly 1
 - if ancount and nscounts fields are exactly 0
 - if arcount is either 0 or 1
 - if the length of the packet is greater than 12 + 9 bytes (that is
   at least long enough to have query for a two parts domain like "a.b")
 - if the flags field is sane

The last check is important. During normal operation we want to accept
DNS flags:

  - "Recursion Desired"
  - "Recursion Available" (due to a bug in RIPE Atlas probes)
  - "Checking Disabled"

That said, legitimate traffic should only ever have "Checking
Disabled" flag set. To be more strict and ensure "RD" and "RA" flags
are clear supply "--strict" flag.
    ''')

    parser.add_argument('-s', '--strict', action='store_true',
                        help='be more strict, also drop Recursion Desired and Recursion Available flags')
    args = parser.parse_args(args=args)

    if ipversion == 4:
        print "    ld #%i" % (l3_off)
        print "    ldx 4*([%i]&0xf)" % (l3_off,)
        print "    add x"
    elif ipversion == 6:
        # assuming first "next header" is UDP
        print "    ld #%i" % (l3_off + 40) # 40B of ipv6
    print "    tax"
    print "    ; x points to start of UDP header"
    print "    ; load udp header + payload length"
    print "    ldh [x + 4]"
    print "    ; valid udp payload length must be > 12 + 9 (assuming a.b query)"
    print "    jlt #%i, match" % (8 + 12 + 9)
    print
    print "    txa"
    print "    add #8"
    print "    tax"
    print "    ; x points to start of DNS"
    print

    print "    ; allow only flags:"
    # rfc6840 says CD should always be set
    print "    ;   4: checking_disabled"
    # and AD might be set on queries:
    #   http://tools.ietf.org/html/rfc6840#page-10
    print "    ;   5: authenticated_data"
    print "    ;   6: zflag"
    flags = 0xffff
    flags &= ~(1 << 4)
    flags &= ~(1 << 5)
    flags &= ~(1 << 6)
    if not args.strict:
        print "    ;   8: recursion_desired"
        print "    ;   9: recursion_available"
        # there is some background noise of RD
        flags &= ~(1 << 8)
        # RIPE Atlas probes set RA flag in requests. Ugly.
        flags &= ~(1 << 9)
    print "    ldh [x + 2]        ; opcode = 0, rdcode = 0 etc"
    print "    and #0x%04x" % flags
    print "    jne #0, match"
    print
    print "    ldh [x + 4]        ; qdcount must be 1"
    print "    jneq #0x1, match"
    print "    ld [x + 6]         ; ancount and nscount must be 0"
    print "    jneq #0x0, match"
    print "    ldh [x + 10]       ; arcount must be 0 or 1"
    print "    jgt #0x1, match"
    print "    ret #%i" % (0 if not negate else 65535)
    print
    print "match:"
    print "    ret #%i" % (65535 if not negate else 0)

    if args.strict:
        return 'strict'
    return ''
