import argparse
import itertools
import string
import struct
import sys


# Accepts list of tuples [(mergeable, value)] and merges fields where
# mergeable is True.
def merge(iterable, merge=lambda a,b:a+b):
    for k, g in itertools.groupby(iterable, key=lambda a:a[0]):
        if k is True:
            yield reduce(merge, (i[1] for i in g))
        else:
            for i in g:
                yield i[1]


ACCEPTABLE_CHARS = set(string.printable) - set(string.whitespace) - set(string.punctuation)

def gen(args, l3_off=0, ipversion=4, negate=False):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        prog="%s dns --" % (sys.argv[0]),
        description=r'''

This tool creates a raw Berkeley Packet Filter (BPF) rule that will
match packets which are DNS queries against listed domains. For
example:

  %(prog)s example.com

will print a BPF rule matching all packets that look like a DNS packet
first query being equal to "example.com". Another example:

  %(prog)s *.www.fint.me

will match packets that have a any prefix (subdomain) and exactly
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

Question mark '?' matches exactly one characer. For example this rule:

  %(prog)s fin?.me

will match:

   fint.me, finT.me, finX.me, finZ,me

but will not match:

   finXX.me, fiXX.me, www.finX.me, fin.me

You can create a single rule matching than one domain:

  %(prog)s example.com *.www.fint.me

The "--ignorecase" option will produce BPF bytecode that matches
domains in case insensitive way. Beware, the genrated bytecode will be
significantly longer.

Leading and trailing dots are ignored, this commands are equivalent:

  %(prog)s example.com fint.me
  %(prog)s .example.com fint.me.

A special consideration is given if the suffix is '**' (star
star). This is interperted as "any suffix", for example this:

  %(prog)s example.**

Will match:

   example.com example.de example.co.uk example.anything.whatsoever

But not:

   www.example.com eexample.com
''')

    parser.add_argument('-i', '--ignorecase', action='store_true',
                        help='match domains in case-insensitive way')
    parser.add_argument('domains', nargs='*',
                        help='DNS domain patterns to match on')

    args = parser.parse_args(args)

    if not args.domains:
        parser.print_help()
        sys.exit(-1)


    list_of_rules = []

    for domain in args.domains:
        # remove trailing and leading whitespace
        domain = domain.strip().lstrip(".")

        if domain.endswith('**'):
            free_suffix = True
            domain = domain[:-2]
        else:
            free_suffix = False

        # Ensure the trailing dot
        domain = domain.rstrip(".")
        if not free_suffix:
            domain += '.'

        rule = []
        for part in domain.split("."):
            if part == '*':
                rule.append( (False, '*') )
            else:
                rule.append( (True, [(False, chr(len(part)))] \
                                  + [(True, c) for c in part]) )

        list_of_rules.append( list(merge(rule)) )

    def match_exact(rule, label, last=False):
        mask = []
        for is_char, b in rule:
            if is_char and b == '?':
                mask.append( '\xff' )
            elif is_char and args.ignorecase:
                mask.append( '\x20' )
            elif not is_char and last and free_suffix:
                # ignore the length of last part if free_suffix
                mask.append( '\xff' )
            else:
                # else, literal matching
                mask.append( '\x00' )
        mask = ''.join(mask)
        s = ''.join(map(lambda (is_char, b): b, rule))
        print "    ; Match: %s %r  mask=%s" % (s.encode('hex'), s, mask.encode('hex'))
        off = 0
        while s:
            if len(s) >= 4:
                m, s = s[:4], s[4:]
                mm, mask = mask[:4], mask[4:]
                m, = struct.unpack('!I', m)
                mm, = struct.unpack('!I', mm)
                print "    ld [x + %i]" % off
                if mm:
                    print "    or #0x%08x" % mm
                    m |= mm
                print "    jneq #0x%08x, %s" % (m, label,)
                off += 4
            elif len(s) >= 2:
                m, s = s[:2], s[2:]
                mm, mask = mask[:2], mask[2:]
                m, = struct.unpack('!H', m)
                mm, = struct.unpack('!H', mm)
                print "    ldh [x + %i]" % off
                if mm:
                    print "    or #0x%04x" % mm
                    m |= mm
                print "    jneq #0x%04x, %s" % (m, label,)
                off += 2
            else:
                m, s = s[:1], s[1:]
                m, = struct.unpack('!B', m)
                mm, mask = mask[:1], mask[1:]
                mm, = struct.unpack('!B', mm)
                print "    ldb [x + %i]" % off
                if mm:
                    print "    or #0x%02x" % mm
                    m |= mm
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

    if ipversion == 4:
        print "    ldx 4*([%i]&0xf)" % (l3_off,)
        print "    ; l3_off(%i) + 8 of udp + 12 of dns" % (l3_off,)
        print "    ld #%i" % (l3_off + 8 + 12) # 8B of udp + 12B of dns header
        print "    add x"
    elif ipversion == 6:
        # assuming first "next header" is UDP
        print "    ld #%i" % (l3_off + 40 + 8 + 12) # 40B of ipv6 + 8B of udp + 12B of dns header

    print "    tax"
    print "    ; a = x = M[0] = offset of first dns query byte"
    print "    %sst M[0]" % ('' if len(list_of_rules) > 1 else '; ',)
    print

    for i, rules in enumerate(list_of_rules):
        print "lb_%i:" % (i,)
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

    name_parts = []
    for domain in args.domains:
        if domain[0] == '-':
            continue

        domain = domain.strip(".").strip()
        parts = []
        for part in domain.split("."):
            if part == '*':
                parts.append( 'any' )
            else:
                parts.append( ''.join(c if c in ACCEPTABLE_CHARS else 'x'
                                      for c in part) )
        name_parts.append( '_'.join(parts) )
    return '_'.join(name_parts)

