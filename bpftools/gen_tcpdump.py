import argparse
import os
import re
import subprocess
import sys

from . import linktypes

FAKE_PCAP="d4 c3 b2 a1 02 00 04 00  00 00 00 00 00 00 00 00  00 00 01 00 %02x 00 00 00".replace(' ','')


def bpf_from_expr(expr, linktype):
    fake_pcap = (FAKE_PCAP % (linktype,)).decode('hex')

    for path in ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin']:
        tcpdump = os.path.join(path, 'tcpdump')
        if os.path.exists(tcpdump):
            break
    else:
        raise ValueError("Can't find tcpdump executable! run: apt-get install tcpdump")

    if expr.strip().startswith('-'):
        raise ValueError("")

    p = subprocess.Popen([tcpdump, '-r-', '-d', expr], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate(fake_pcap)
    if p.returncode != 0:
        raise ValueError("tcpdump exited with %d %r" % (p.returncode, stderr))
    return stdout.strip()


def gen(params, l3_off=0, ipversion=4, negate=False):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        prog="%s tcpdump --" % (sys.argv[0]),
        description=r'''

Generate bpf using tcpdump pcap compiler. Sadly for now it's done by
shelling out to tcpdump.

''')
    parser.add_argument('expr', nargs='+',
                        help='tcpdump expression')
    args = parser.parse_args(args=params)


    # map offset to linktype heuristics
    vlan = False
    if l3_off == 0:
        if ipversion == 4:
            lt = linktypes.LINKTYPE_IPV4
        if ipversion == 6:
            lt = linktypes.LINKTYPE_IPV6
    elif l3_off == 14:
        lt = linktypes.LINKTYPE_ETHERNET
    elif l3_off == 16:
        lt = linktypes.LINKTYPE_LINUX_SLL
    elif l3_off == 18:
        vlan = True
        lt = linktypes.LINKTYPE_ETHERNET
    else:
        assert False, 'l3_off of %d not supported' % (l3_off,)

    expr = ' '.join(args.expr)
    if negate:
        expr = "not (%s)" % (expr,)
    if vlan:
        expr = "vlan and (%s)" % (expr,)

    code = bpf_from_expr(expr, lt)
    print "; ipver=%s" % (ipversion,)
    print "; %s" % (expr,)
    print
    for line in code.split('\n'):
        lno, _ , rest = line.partition(" ")
        rest = rest.replace("#pktlen", "#len")
        lno = int(lno[1:-1])
        print "l%03d:" % (lno,)
        m = re.match("^(?P<prefix>.*)\s+jt (?P<jt>\d+)\s+jf (?P<jf>\d+)$", rest)
        if m:
            d = m.groupdict()
            print "    %s, l%03d, l%03d" % (d['prefix'].strip(), int(d['jt']), int(d['jf']))
        else:
            print "    %s" % (rest,)
