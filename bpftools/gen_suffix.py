import argparse
import string
import struct
import sys


def gen(args, l3_off=0, ipversion=4, negate=False):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        prog="%s suffix --" % (sys.argv[0]),
        description=r'''

Generate a BPF rule that will match packets based on a given hex
encoded suffix. For example to match packets ending with 010203:

  %(prog)s 010203

This is the same as:

  %(prog)s 01 02 03
    ''')

    parser.add_argument('suffix', nargs='*',
                        help='hex encoded suffix (spaces are ignored)')

    args = parser.parse_args(args)

    suffix_hex = ''.join(args.suffix)

    if not suffix_hex:
        parser.print_help()
        sys.exit(-1)

    assert len(suffix_hex) % 2 == 0

    print "    ld #len"
    print "    sub #%i" % (len(suffix_hex) / 2,)
    print "    tax"
    print

    suffix_hex = suffix_hex.rstrip('x')
    s = suffix_hex.decode('hex')

    off = 0
    print "     ; matching %s" % (s.encode('hex'),)
    print "     ;         %r" % (s,)
    while s:
        if len(s) >= 4:
            m, s = s[:4], s[4:]
            m, = struct.unpack('!I', m)
            print "    ld [x + %i]" % off
            print "    jneq #0x%08x, nomatch" % (m, )
            off += 4
        elif len(s) >= 2:
            m, s = s[:2], s[2:]
            m, = struct.unpack('!H', m)
            print "    ldh [x + %i]" % off
            print "    jneq #0x%04x, nomatch" % (m, )
            off += 2
        else:
            m, s = s[:1], s[1:]
            m, = struct.unpack('!B', m)
            print "    ldb [x + %i]" % off
            print "    jneq #0x%02x, nomatch" % (m, )
            off += 1
    print "    ret #%i" % (65535 if not negate else 0)
    print ""
    print "nomatch:"
    print "    ret #%i" % (0 if not negate else 65535)

    return suffix_hex
