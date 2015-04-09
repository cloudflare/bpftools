import argparse
import string
import sys


def gen(params, l3_off=0, ipversion=4, negate=False):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        prog="%s badrand --" % (sys.argv[0]),
        description=r'''

Generate raw BPF rules that match packets formed with predicitable
(non)random fields.  In some specific packets, the IP Identifier field
could have the value of thebyte swaped TCP/UDP Source port. This is
what is detected by this BPF rule.

''')

    if ipversion == 4:
        print "    ; Load IP header length into X"
        print "    ldx 4*([%i]&0xf)" % (l3_off,)
        print "    ; Loading TCP/UDP byte 1 port into A: %s + X + 1" % (l3_off,)
        print "    ldb [x + %i]" % (l3_off + 1,)
        print "    lsh #8"
        print "    st M[%i]" % (0,)
        print "    ; Load another byte: %s + X + 0" % (l3_off,)
        print "    ldb [x + %i]" % (l3_off,)         # Loading TCP/UDP byte 0 port into A
        print "    ldx M[%i]" % (0,)                 # Loading M[0] (UDP port shifted byte 1) into X
        print "    ; A holds the byte 0 of the TCP/UDP port and X the byte 1"
        print "    or x"                            # Oring A and X
        print "    ; ORing these values into X"
        print "    tax"
        print "    ; X now contains shuffled port number"

        print "    ; Load IPID into A"
        print "    ldh [%i]" % (l3_off + 4,)         # Loading IP identifier into A
        print "    ; Compare with X"
        print "    sub x"
        print "    ; If the result is equal to 0 it means IP ID is equal to the byte swaped port"
        print "    jeq #0x0, match"
        print "    ret #%i" % (0 if not negate else 1,)
        print "match:"
        print "    ret #%i" % (1 if not negate else 0,)

    if ipversion == 6:
        print "    ; ipv6 not supported, no ipid. Never match"
        print "    ret #%i" % (0 if not negate else 1,)

    return ''
