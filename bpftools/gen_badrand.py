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
        print "    ldx 4*([%i]&0xf)" % (l3_off)     # IHL value
        print "    ldb [x + %i]" % (l3_off + 1)     # Loading TCP/UDP byte 1 port into A
        print "    lsh #8"                          # Bit shifting
        print "    st M[%i]" % (0)                  # Storing A into M[0]
        print "    ldb [x + %i]" % (l3_off)         # Loading TCP/UDP byte 0 port into A
        print "    ldx M[%i]" % (0)                 # Loading M[0] (UDP port shifted byte 1) into X
        print "    ; A holds the byte 0 of the TCP/UDP port and X the byte 1"
        print "    or x"                            # Oring A and X
        print "    ; ORing these values into X"
        print "    tax"

        print "    ldh [%i]" % (l3_off + 4)         # Loading IP identifier into A
        print "    ; Loading IP ID into A and XORing A with X"
        print "    xor x"                           # Xoring A and X (Port and IP ID)
        print "    ; If the result is equal to 0 it means IP ID is equal to the byte swaped port"
        print "    jeq #0x0, match"
        print "    ret #%i" % (0 if not negate else 1)
        print "    match:"
        print "    ret #%i" % (1 if not negate else 0)

    return ''
