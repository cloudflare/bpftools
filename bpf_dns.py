#!/usr/bin/env python

import getopt
import sys
import struct
import StringIO as stringio

import utils


def usage():
    print r"""
bpf_dns.py [ OPTIONS ] [ domain... ]

This tool creates a raw Berkeley Packet Filter (BPF) rule that will
match IPv4 packets which are DNS queries against listed domains. For
example:

  bpf.py example.com

will print a BPF rule matching all packets that look like a DNS packet
first query being equal to "example.com". Another example:

  bpf.py *.www.fint.me

will matchd packets that have a any prefix (subdomain) and exactly
"www.fint.me" as suffix. It will match:

    blah.www.fint.me
    anyanyany.www.fint.me

but it will not match:

   www.fint.me
   blah.blah.www.fint.me

Also, star has a special meaning only if it's a sole part of
subdomain: "*xxx.example.com" is treated as a literal star, so is
"xxx*.example.com". On the other hand "xxx.*.example.com" will have a
wildcard meaning.

You can create a single rule matching than one domain:

  bpf.py example.com *.www.fint.me

Leading and trailing dots are ignored, this commands are equivalent:

  bpf.py example.com fint.me
  bpf.py .example.com fint.me.

Options are:
  -h, --help         print this message
  -n, --negate       capture packets that don't match given domains
  -i, --ignore-case  make the rule case insensitive. use with care.
  -s, --assembly     print BPF assembly instead of byte code
  -o, --offset       ofset of l3 (IP) header, 14 by default
""".lstrip()
    sys.exit(2)


def main():
    ignorecase = negate = assembly = False

    l3_off = 14

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hinso:",
                                   ["help", "ignore-case", "negate",
                                    "assembly", "offset="])
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
        elif o in ("-o", "--offset"):
            l3_off = int(a)
        else:
            assert False, "unhandled option"

    if not args:
        print >> sys.stderr, "At least one domain name required."
        sys.exit(-1)

    if not assembly:
        sys.stdout, saved_stdout = stringio.StringIO(), sys.stdout


    list_of_rules = []

    for domain in args:
        # remove trailing and leading dots and whitespace
        domain = domain.strip(".").strip()

        # keep the trailing dot
        domain += '.'

        rule = []
        for part in domain.split("."):
            if part == '*':
                rule.append( (False, '*') )
            else:
                rule.append( (True, chr(len(part)) + part) )

        list_of_rules.append( list(utils.merge(rule)) )

    def match_exact(s, label, last=False):
        print "    ; Match: %s %r" % (s.encode('hex'), s)
        off = 0
        while s:
            if len(s) >= 4:
                m, s = s[:4], s[4:]
                m, = struct.unpack('!I', m)
                print "    ld [x + %i]" % off
                if ignorecase:
                    print "    or #0x20202020"
                    m |= 0x20202020
                print "    jneq #0x%08x, %s" % (m, label,)
                off += 4
            elif len(s) >= 2:
                m, s = s[:2], s[2:]
                m, = struct.unpack('!H', m)
                print "    ldh [x + %i]" % off
                if ignorecase:
                    print "    or #0x2020"
                    m |= 0x2020
                print "    jneq #0x%04x, %s" % (m, label,)
                off += 2
            else:
                m, s = s[:1], s[1:]
                m, = struct.unpack('!B', m)
                print "    ldb [x + %i]" % off
                if ignorecase:
                    print "    or #0x20"
                    m |= 0x20
                print "    jneq #0x%02x, %s" % (m, label,)
                off += 1
        if not last:
            print "    txa"
            print "    add #%i" % (off,)
            print "    tax"

    def match_star():
        print "    ; Match: *"
        print "    ldb [x + 0]"
        print "    add x"
        print "    add #1"
        print "    tax"

    print "    ld #%i" % (l3_off + 8 + 12) # 8B of udp + 12B of dns header
    print "    ldx 4*([%i]&0xf)" % (l3_off,)
    print "    add x"
    print "    tax"
    print "    ; x = M[0] = offset of first dns query byte"
    print "    %sst M[0]" % ('' if len(list_of_rules) > 1 else '; ',)
    print

    for i, rules in enumerate(list_of_rules):
        print "lb_%i:" % (i,)
        print "    ; %r" % (rules,)
        print "    %sldx M[0]" % ('' if i != 0 else '; ')
        for j, rule in enumerate(rules):
            last = (j == len(rules)-1)
            if rule != '*':
                match_exact(rule, 'lb_%i' % (i+1,), last)
            else:
                match_star()
        print "    ret #%i" % (1 if not negate else 0)
        print

    print "lb_%i:" % (i+1,)
    print "    ret #%i" % (0 if not negate else 1)


    sys.stdout.flush()

    if not assembly:
        assembly = sys.stdout.seek(0)
        assembly = sys.stdout.read()
        sys.stdout = saved_stdout
        print utils.bpf_compile(assembly)


if __name__ == "__main__":
    main()
