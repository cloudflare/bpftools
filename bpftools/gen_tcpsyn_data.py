import argparse
import string
import sys

def gen(params, l3_off=0, ipversion=4, negate=False):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        prog="%s tcpsyn_data --" % (sys.argv[0]),
        description=r'''

Generate raw BPF rules matching SYN packets with a payload.
It works on both IPV6 and IPV4. IPV6 extension headers are not supported.
This rule returns match if the packet is SYN only and has a IP total length field
which is bigger than IP header length added to the TCP header length.

If this bigger that means there are some data -> this matches SYN packet with data.
It does not match all the other packets.

IPV4 successfully manually tested on 25 packets.

''')
    
    if ipversion == 6:
        frame_size_off = 4
        protocol_value_off = 6
        print "ldx #40"  				# No extension header support

    if ipversion == 4:
        frame_size_off = 2
        protocol_value_off = 9
        print "ldx 4*([%i]&0xf)" % (l3_off)  		# IHL value in X

    print "ldh [%i]" % (l3_off + frame_size_off)	# Global frame size in m[1]
    print "st M[1]" 
    print "ldb [%i]" % (l3_off + protocol_value_off)	# Protocol value in A

    print "jneq #0x06, nonmatch" 			#0x06 is TCP protocol in IPV4/IPV6

    # The following code is TCP related

    print "ldb [x + %i]" % (l3_off + 13)
    print "and #0x12" 					#00010010 : only ACK and SYN bits matter
    # Total frame length - IP header length = TCP data offset

    print "jneq #0x2, nonmatch" 			# We do not match packets if value is 0 or 00010000 or 00010010 
    
    print "ld M[1]" 
    print "sub x"    					# Result in A
    print "st M[3]"  					# Result in M[3]
    
    print "ldb [x + %i]" % (l3_off + 12)
    print "rsh #0x4"  					# The TCP header size is stored on the 4 MSB...
    print "mul #0x4"  					# ...value which is stored in 32bits words... need the value in bytes in A
    
    #We do not need the value stored in X anymore can use it
    print "ldx M[3]"

    print "sub x" 					#Should be 0
    print "jeq #0x0, nonmatch" #If is 0 it does not match, the packet is valid

    print "match:"
    print "ret #%i" % (1 if not negate else 0)

    print "nonmatch:"
    print "ret #%i" % (0 if not negate else 1)

    return ''

