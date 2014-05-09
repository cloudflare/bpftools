#!/usr/bin/env python

import getopt
import os
import pcappy
import string
import sys


def usage():
    print r"""
offset.py [ OPTIONS ] string [ pcap file... ]

Find an offset of a string in packet. Packets are read from given pcap
files or from stdin. The string is decoded so might contain things
like '\x00' or '\t'.

Options are:
  -h, --help         print this message
  -r, --reverse      the offset from the end, not the start of the packet
  -p, --prefix       print hex encoded bytes up to the matched string
  -s, --suffix       print hex encoded bytes from the matched string onwards
  -i, --ignore       ignore lines that don't contain the string
""".lstrip()
    sys.exit(2)

def main():
    reverse = prefix = suffix = ignore = False

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hrpsi",
                                   ["help", "reverse", "prefix", "suffix",
                                    "ignore"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-r", "--reverse"):
            reverse = True
        elif o in ("-p", "--prefix"):
            prefix = True
        elif o in ("-s", "--suffix"):
            suffix = True
        elif o in ("-i", "--ignore"):
            ignore = True
        else:
            assert False, "unhandled option"

    if not args:
        assert False, "first argument must be a string to match"

    match, args = args[0], args[1:]
    if not args:
        readfds = [sys.stdin]
    else:
        readfds = [open(fname, 'rb') for fname in args]

    # Important. The first parameter may be encoded like '\x00'
    match = match.decode("string_escape")

    for fd in readfds:
        p = pcappy.open_offline(fd)
        while True:
            r = p.next_ex()
            if r is None:
                break
            hdr, data = r

            o = string.find(data, match)
            if ignore and o == -1:
                continue

            l = [str(o if not reverse else o - len(data))]
            if o != -1:
                if prefix:
                    l.append( data[:o].encode('hex') )
                if suffix:
                    l.append( data[o:].encode('hex') )
            else:
                if prefix or suffix:
                    l.append( data.encode('hex') )
            print '\t'.join(l)

    sys.stdout.flush()

    # normal exit crashes due to a double free error in pcappy
    os._exit(0)


if __name__ == "__main__":
    try:
        main()
    except IOError, e:
        if e.errno == 32:
            os._exit(-1)
        raise
    except KeyboardInterrupt:
        os._exit(-1)
