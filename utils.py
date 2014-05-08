
import itertools
import os
import subprocess
import sys


def find_binary(prefixes, name, args):
    for prefix in prefixes:
        try:
            subprocess.call([os.path.join(prefix, name)] + args)
        except OSError, e:
            continue
        return prefix
    print >> sys.stderr, prefix, "%r tool not found in your PATH" % (name,)
    os._exit(-2)


def bpf_compile(assembly):
    prefixes = [".", "linux_tools", os.path.dirname(sys.argv[0]),
                os.path.realpath(os.path.dirname(sys.argv[0]))]
    prefix = find_binary(prefixes, "bpf_asm", ['/dev/null'])

    out, err = subprocess.Popen([os.path.join(prefix, "bpf_asm")],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE).communicate(assembly)

    if set(out) - set(" ,0123456789\n") or not out:
        print >> sys.stderr, "Compiling failed with:\n%s\n" % (out.strip() + err.strip())
        os._exit(-3)
    return out.strip()


# Accepts list of tuples [(mergeable, value)] and merges fields where
# mergeable is True.
def merge(iterable, merge=lambda a,b:a+b):
    for k, g in itertools.groupby(iterable, key=lambda a:a[0]):
        if k is True:
            yield reduce(merge, (i[1] for i in g))
        else:
            for i in g:
                yield i[1]


def _looks_like_ip(l2, off):
    ipver, _, total_length = struct.unpack_from('!BBH', l2, off)
    if (ipver & 0xF0 == 0x40 and (ipver & 0x0f) >= 5
        and total_length + off == len(l2)):
        return 4

    vertos, _, _,  pay_len, proto, ttl = struct.unpack_from('!BBHHBB', l2, off)
    if (vertos & 0xF0 == 0x60 and pay_len + off + 40 == len(l2)
        and ttl > 0):
        return 6
    return None

def find_ip_offset(l2, max_off=40):
    # first look for both ethernet and ip header
    for off in xrange(2, max_off+2, 2):
        if l2[off-2:off] == '\x08\x00' and _looks_like_ip(l2, off) == 4:
            return off
        if l2[off-2:off] == '\x86\xdd' and _looks_like_ip(l2, off) == 6:
            return off

    # okay, just look for ip header
    for off in xrange(0, max_off, 2):
        if _looks_like_ip(l2, off):
            return off

    raise Exception("can't find an IP header")
