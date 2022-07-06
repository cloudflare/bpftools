import os
import struct
import subprocess
import sys

from pkg_resources import resource_filename
from binascii import hexlify
from binascii import unhexlify

def find_binary(prefixes, name, args):
    for prefix in prefixes:
        try:
            subprocess.call([os.path.join(prefix, name)] + args)
        except OSError, e:
            continue
        return prefix
    print >> sys.stderr, prefix, "%r not found in your PATH nor LINUX_TOOLS_PATH" % (name,)
    os._exit(-2)


def bpf_compile(assembly):
    prefixes = ["",
                resource_filename(__name__, "."),
                resource_filename(__name__, os.path.join("..","linux_tools")),
                resource_filename(__name__, "linux_tools"),
                ".",
                "linux_tools",
                os.path.dirname(sys.argv[0]),
                os.path.realpath(os.path.dirname(sys.argv[0])),
                os.getenv("LINUX_TOOLS_PATH", "."),
                ]
    prefix = find_binary(prefixes, "bpf_asm", ['/dev/null'])

    out, err = subprocess.Popen([os.path.join(prefix, "bpf_asm")],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE).communicate(assembly)

    if set(out) - set(" ,0123456789\n") or not out:
        print >> sys.stderr, "Compiling failed with:\n%s\n" % (out.strip() + err.strip())
        os._exit(-3)
    return out.strip()


def _looks_like_ip(l2, off):
    if len(l2) - off >= 20:
        ipver, _, total_length = struct.unpack_from('!BBH', l2, off)
        if (ipver & 0xF0 == 0x40 and (ipver & 0x0f) >= 5):
            return 4

    if len(l2) - off >= 40:
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

    return None

def scrub_byte(data, minval, maxval, ip_constant):
    if not (ord(data) >= minval and ord(data) < maxval):
        return data
    ip_byte_str = hexlify(data)
    ip_byte_int = int(ip_byte_str, 16)
    ip_byte_int = ip_byte_int - minval
    obfuscated_byte = (ip_byte_int + ip_constant) % (maxval-minval)
    obfuscated_byte = obfuscated_byte + minval
    obfuscated_str = format(obfuscated_byte,'x')
    if len(obfuscated_str) == 1:
        obfuscated_str = "0" + obfuscated_str
    obfuscated_str = unhexlify(obfuscated_str.rstrip(b"\n"))
    return obfuscated_str

def scrub_dns_name(data, ip_ihl, ip_hdr_off, entropy):
    # UDP
    dns_hdr_off = ip_ihl + ip_hdr_off + 8 # 8 is UDP header size
    str_len_offset = 0
    name_offset = 0
    while True:
        try:
            str_len_off = ord(data[dns_hdr_off + 12 + name_offset]) # 12 is the offset inside the DNS packet
        except IndexError:
             print >> sys.stderr, "OOps, it seems this UDP packet is not properly formed DNS, break while True"
             break
        if str_len_off == 0:
            break
        idx = 0
        while idx < str_len_off:
            try:
                rtr = data[dns_hdr_off + 12 + name_offset + idx + 1]
            except IndexError:
                print >> sys.stderr, "OOps, it seems this UDP packet is not properly formed DNS, break while idx"
                break
            rtr = scrub_byte(rtr, ord('a'), ord('z') + 1, entropy[name_offset % len(entropy)])
            rtr = scrub_byte(rtr, ord('A'), ord('Z') + 1, entropy[name_offset % len(entropy)])
            rtr = scrub_byte(rtr, ord('0'), ord('9') + 1, entropy[name_offset % len(entropy)])
            data[dns_hdr_off + 12 + name_offset + idx + 1] = rtr
            idx = idx + 1
        name_offset = name_offset + str_len_off + 1


def do_scrub(l2, ip_hdr_off):
    entropy = [11,2,9,7,5,10,17,19,1,3,15]

    data = list(l2)
    if ip_hdr_off == 18:
        #Ethernet with vlan
        data[12] = '\x08'
        data[13] = '\x00'
        del data[14:18]
        ip_hdr_off = 14

    if ip_hdr_off not in (14, 16):
        raise Exception("ip_hdr_off=%i Not ethernet, not sure how to scrub MACS" % ip_hdr_off)
    for i in xrange(ip_hdr_off-2):
        data[i] = '\x00'

    ipver = ord(data[ip_hdr_off])
    if ipver & 0xF0 == 0x40: 
        # IPV4
        # Scrubbing IPs
        ip_ihl = (ipver & 0x0F)*4
        for i in xrange(ip_hdr_off+12, ip_hdr_off+12+4+4, 1):
            data[i] = scrub_byte(data[i], 0, 256, entropy[i % len(entropy)])
        if ord(data[ip_hdr_off+9]) == 0x11:
            # UDP
            scrub_dns_name(data, ip_ihl, ip_hdr_off, entropy)
    elif ipver & 0xF0 == 0x60:
        # IPV6
        for i in xrange(ip_hdr_off+8, ip_hdr_off+8+16+16, 1):
            data[i] = scrub_byte(data[i], 0, 256, entropy[i % len(entropy)])
        if ord(data[ip_hdr_off+6]) == 0x11:
            # UDP
            scrub_dns_name(data, 40, ip_hdr_off, entropy)
    return ''.join(data)
