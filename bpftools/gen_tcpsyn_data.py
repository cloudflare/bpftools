import argparse
import string
import sys

def gen(params, l3_off=0, ipversion=4, negate=False):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        prog="%s tcpsyn_data --" % (sys.argv[0]),
        description=r'''

Ble

''')

    if ipversion == 6:
        frame_size_off = 4
        protocol_value_off = 6
        print "ldx #40"      # No extension header support

    if ipversion == 4:
        frame_size_off = 2
        protocol_value_off = 9
        print "ldx 4*([%i]&0xf)" % (l3_off)  # IHL value in X

    print "ldh [%i]" % (l3_off + frame_size_off)      # Global frame size in m[1]
    print "st M[1]" 
    print "ldb [%i]" % (l3_off + protocol_value_off)      # Protocol value in A

    print "jneq #0x06, nonmatch" #0x06 is TCP protocol in IPV4/IPV6

    # The following code is TCP related

    print "ldb [x + %i]" % (l3_off + 13)
    print "and #0x12" #00010010 : only ACK and SYN bits matter
    # Total frame length - IP header length = TCP data offset

    print "jneq #0x2, nonmatch" #Error if value is 0 or 00010000 or 00010010 
    
    print "ld M[1]" 
    print "sub x"    #result in A
    print "st M[3]" #result in M[3]
    
    print "ldb [x + %i]" % (l3_off + 12)
    print "rsh #0x4" # The TCP header size is stored on the 4 MSB...
    print "mul #0x4" # ...value which is stored in 32bits words... need the value in bytes in A
    
    #We do not need the value stored in X anymore can use it
    print "ldx M[3]"

    print "sub x" #Should be 0
    print "jneq #0x0, nonmatch"

    print "match:"
    print "ret #%i" % (1 if not negate else 0)

    print "nonmatch:"
    print "ret #%i" % (0 if not negate else 1)

    return ''

