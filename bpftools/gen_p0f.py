#!/usr/bin/env python3

from __future__ import print_function
import argparse
import sys

from . import p0f
from . import gen_tcpdump


def gen(params, l3_off=0, ipversion=4, negate=False):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        prog="%s p0f --" % (sys.argv[0]),
        description=r"""

Generate bpf using a p0f signature string.

""",
    )
    parser.add_argument("p0f", nargs=1, help="p0f signature")
    args = parser.parse_args(args=params)

    p = p0f.P0fBPF(args.p0f[0])
    for l in p.doc_bpf_str.split("\n"):
        print("; " + l)
    print(";")
    gen_tcpdump.gen([p.bpf_str], l3_off, ipversion, negate)
