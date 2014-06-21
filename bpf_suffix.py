#!/usr/bin/env python

import getopt
import sys
import struct
import StringIO as stringio

import utils


def usage():
    """
""".lstrip()
    sys.exit(2)


def main():
    negate = assembly = False

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hns",
                                   ["help", "negate", "assembly"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-i", "--ignore-case"):
            ignorecase = True
        elif o in ("-n", "--negate"):
            negate = True
        elif o in ("-s", "--assembly"):
            assembly = True
        else:
            assert False, "unhandled option"

    if len(args) != 1:
        print >> sys.stderr, "Supply hex suffix"
        sys.exit(-1)

    if not assembly:
        sys.stdout, saved_stdout = stringio.StringIO(), sys.stdout


    suffix_hex = args[0]
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
    print "    ret #%i" % (1 if not negate else 0)
    print ""
    print "nomatch:"
    print "    ret #%i" % (0 if not negate else 1)

    sys.stdout.flush()

    if not assembly:
        assembly = sys.stdout.seek(0)
        assembly = sys.stdout.read()
        sys.stdout = saved_stdout
        print utils.bpf_compile(assembly)


if __name__ == "__main__":
    main()
