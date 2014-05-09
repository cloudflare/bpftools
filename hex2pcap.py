#!/usr/bin/env python

import getopt
import os
import pcappy
import sys


def usage():
    print """
hex2pcap.py [ OPTIONS ] [ hex file... ]

Read hex packets from stdin or given files and print a pcap file to
stdout. Input lines starting with hash or semicolon are ignored, only
part of a line before tab character is parsed as hex.

Options are:
  -h, --help         print this message
""".lstrip()
    sys.exit(2)


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        else:
            assert False, "unhandled option"

    if not args:
        readfds = [sys.stdin]
    else:
        readfds = [open(fname, 'rb') for fname in args]

    dump = pcappy.PcapPyDead(snaplen=65536).dump_open(sys.stdout)
    hdr = {'ts':{'tv_sec':0, 'tv_usec':0}}

    for fd in readfds:
        for line in fd:
            line = line.lstrip()
            if not line or line[0] in '#;':
                continue
            h, _, _ = line.partition("\t")
            if not h:
                continue
            raw = h.rstrip().decode('hex')

            hdr['caplen'] = hdr['len'] = len(raw)
            dump.write(hdr, raw)

    sys.stdout.flush()
    dump.flush()

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
