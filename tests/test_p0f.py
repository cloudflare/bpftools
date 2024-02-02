#!/usr/bin/env python3

from __future__ import division
from past.utils import old_div
import sys
import logging
import subprocess
import unittest

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import bpftools


class TestP0f(unittest.TestCase):
    def _test_p0f(self, packet, p0f, should_match):
        wrpcap("/tmp/p0f.pcap", packet)
        p0f_bpf = bpftools.gen_p0f.p0f.P0fBPF(p0f)

        proc = subprocess.Popen(
            ["/usr/sbin/tcpdump", "-r", "/tmp/p0f.pcap", "-n", "%s" % p0f_bpf.bpf_str],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        match = True if proc.stdout.readline() != "" else False

        self.assertEqual(match, should_match)

    def test_ttl(self):
        # random
        packet = old_div(old_div(Ether(), IP(ttl=128)), TCP())
        p0f_str = "4:255-:*:*:*,*:::*"
        self._test_p0f(packet, p0f_str, True)

        # fixed (128)
        packet = old_div(old_div(Ether(), IP(ttl=128)), TCP())
        p0f_str = "4:128:*:*:*,*:::*"
        self._test_p0f(packet, p0f_str, True)

        # fixed (64, should be 128)
        packet = old_div(old_div(Ether(), IP(ttl=64)), TCP())
        p0f_str = "4:128:*:*:*,*:::*"
        self._test_p0f(packet, p0f_str, False)

    def test_ttl_ipv6(self):
        # random
        packet = old_div(old_div(Ether(), IPv6(hlim=128)), TCP())
        p0f_str = "6:255-:*:*:*,*:::*"
        self._test_p0f(packet, p0f_str, True)

        # fixed (128)
        packet = old_div(old_div(Ether(), IPv6(hlim=128)), TCP())
        p0f_str = "6:128:*:*:*,*:::*"
        self._test_p0f(packet, p0f_str, True)

        # fixed (64, should be 128)
        packet = old_div(old_div(Ether(), IPv6(hlim=64)), TCP())
        p0f_str = "6:128:*:*:*,*:::*"
        self._test_p0f(packet, p0f_str, False)

    def test_olen(self):
        # 0
        packet = old_div(old_div(Ether(), IP()), TCP())
        p0f_str = "4:255-:*:*:*,*:::*"
        self._test_p0f(packet, p0f_str, True)

        # 1
        packet = old_div(old_div(Ether(), IP(options=IPOption("\x01\x02\x04"))), TCP())
        p0f_str = "4:255-:1:*:*,*:::*"
        self._test_p0f(packet, p0f_str, True)

        # 1, should be 2
        packet = old_div(old_div(Ether(), IP(options=IPOption("\x01\x02\x04"))), TCP())
        p0f_str = "4:255-:2:*:*,*:::*"
        self._test_p0f(packet, p0f_str, False)

    def test_mss(self):
        # 1460
        packet = old_div(old_div(Ether(), IP()), TCP(options=[("MSS", 1460)]))
        p0f_str = "4:255-:*:1460:*,*:mss::*"
        self._test_p0f(packet, p0f_str, True)

        # 900, should be 1460
        packet = old_div(old_div(Ether(), IP()), TCP(options=[("MSS", 900)]))
        p0f_str = "4:255-:*:1460:*,*:mss::*"
        self._test_p0f(packet, p0f_str, False)

    def test_mss_ipv6(self):
        # 1460
        packet = old_div(old_div(Ether(), IPv6()), TCP(options=[("MSS", 1460)]))
        p0f_str = "6:255-:*:1460:*,*:mss::*"
        self._test_p0f(packet, p0f_str, True)

        # 900, should be 1460
        packet = old_div(old_div(Ether(), IPv6()), TCP(options=[("MSS", 900)]))
        p0f_str = "6:255-:*:1460:*,*:mss::*"
        self._test_p0f(packet, p0f_str, False)

    def test_wsize_scale(self):
        # 65535, 0
        packet = old_div(
            old_div(Ether(), IP()), TCP(window=65535, options=[("WScale", 0)])
        )
        p0f_str = "4:255-:*:*:65535,0:ws::*"
        self._test_p0f(packet, p0f_str, True)

        # 1,1 should be 65535, 0
        packet = old_div(old_div(Ether(), IP()), TCP(window=1, options=[("WScale", 1)]))
        p0f_str = "4:255-:*:*:65535,0:ws::*"
        self._test_p0f(packet, p0f_str, False)

        # mss*8, 1
        packet = old_div(
            old_div(Ether(), IP()),
            TCP(window=8000, options=[("MSS", 1000), ("WScale", 1)]),
        )
        p0f_str = "4:255-:*:*:mss*8,1:mss,ws::*"
        self._test_p0f(packet, p0f_str, True)

        # mss*4, should be mss*8, 1
        packet = old_div(
            old_div(Ether(), IP()),
            TCP(window=4000, options=[("MSS", 1000), ("WScale", 1)]),
        )
        p0f_str = "4:255-:*:*:mss*8,1:mss,ws::*"
        self._test_p0f(packet, p0f_str, False)

        # mtu*2, 1
        packet = old_div(
            old_div(Ether(), IP()),
            TCP(window=3000, options=[("MSS", 1000), ("WScale", 1)]),
        )
        p0f_str = "4:255-:*:*:mtu*2,1:mss,ws::*"
        self._test_p0f(packet, p0f_str, True)

        # mss*4, should be mtu*3, 1
        packet = old_div(
            old_div(Ether(), IP()),
            TCP(window=4500, options=[("MSS", 1000), ("WScale", 1)]),
        )
        p0f_str = "4:255-:*:*:mtu*2,1:mss,ws::*"
        self._test_p0f(packet, p0f_str, False)

        # %200, 1
        packet = old_div(
            old_div(Ether(), IP()),
            TCP(window=8000, options=[("MSS", 1000), ("WScale", 1)]),
        )
        p0f_str = "4:255-:*:*:%200,1:mss,ws::*"
        self._test_p0f(packet, p0f_str, True)

    def test_wsize_scale_ipv6(self):
        # 65535, 0
        packet = old_div(
            old_div(Ether(), IPv6()), TCP(window=65535, options=[("WScale", 0)])
        )
        p0f_str = "6:255-:*:*:65535,0:ws::*"
        self._test_p0f(packet, p0f_str, True)

        # 1,1 should be 65535, 0
        packet = old_div(
            old_div(Ether(), IPv6()), TCP(window=1, options=[("WScale", 1)])
        )
        p0f_str = "6:255-:*:*:65535,0:ws::*"
        self._test_p0f(packet, p0f_str, False)

        # mss*8, 1
        packet = old_div(
            old_div(Ether(), IPv6()),
            TCP(window=8000, options=[("MSS", 1000), ("WScale", 1)]),
        )
        p0f_str = "6:255-:*:*:mss*8,1:mss,ws::*"
        self._test_p0f(packet, p0f_str, True)

        # mss*4, should be mss*8, 1
        packet = old_div(
            old_div(Ether(), IPv6()),
            TCP(window=4000, options=[("MSS", 1000), ("WScale", 1)]),
        )
        p0f_str = "6:255-:*:*:mss*8,1:mss,ws::*"
        self._test_p0f(packet, p0f_str, False)

        # %200, 1
        packet = old_div(
            old_div(Ether(), IPv6()),
            TCP(window=8000, options=[("MSS", 1000), ("WScale", 1)]),
        )
        p0f_str = "6:255-:*:*:%200,1:mss,ws::*"
        self._test_p0f(packet, p0f_str, True)

    def test_olayout(self):
        # mss, ws, nop, sok, eol
        packet = old_div(
            old_div(Ether(), IP()),
            TCP(options=[("MSS", 1000), ("WScale", 1), ("NOP", ""), ("SAckOK", "")]),
        )
        p0f_str = "4:255-:*:*:*,*:mss,ws,nop,sok,eol::*"
        self._test_p0f(packet, p0f_str, True)

        # (mss, ws, nop, sok, eol) should be (mss, nop, sok, eol)
        packet = old_div(
            old_div(Ether(), IP()),
            TCP(options=[("MSS", 1000), ("WScale", 1), ("NOP", ""), ("SAckOK", "")]),
        )
        p0f_str = "4:255-:*:*:*,*:mss,nop,sok,eol::*"
        self._test_p0f(packet, p0f_str, False)

    def test_olayout_data_off(self):
        # 3, 4 and 5 nops
        packet = old_div(
            old_div(Ether(), IP()),
            TCP(
                options=[
                    ("NOP", ""),
                    ("NOP", ""),
                    ("NOP", ""),
                    ("NOP", ""),
                    ("NOP", ""),
                ]
            ),
        )
        p0f_str = "4:255-:*:*:*,*:nop,nop,nop,nop,nop::*"
        self._test_p0f(packet, p0f_str, True)

        packet = old_div(
            old_div(Ether(), IP()),
            TCP(options=[("NOP", ""), ("NOP", ""), ("NOP", ""), ("NOP", "")]),
        )
        p0f_str = "4:255-:*:*:*,*:nop,nop,nop,nop::*"
        self._test_p0f(packet, p0f_str, True)

        packet = old_div(
            old_div(Ether(), IP()), TCP(options=[("NOP", ""), ("NOP", ""), ("NOP", "")])
        )
        p0f_str = "4:255-:*:*:*,*:nop,nop,nop::*"
        self._test_p0f(packet, p0f_str, True)

    def test_empty_olayout(self):
        packet = old_div(old_div(Ether(), IP()), TCP())
        p0f_str = "4:255-:*:*:*,*:::*"
        self._test_p0f(packet, p0f_str, True)

        packet = old_div(old_div(Ether(), IP()), TCP(options=[("NOP", "")]))
        p0f_str = "4:255-:*:*:*,*:::*"
        self._test_p0f(packet, p0f_str, False)

    def test_eol(self):
        # eol (2)
        packet = old_div(
            old_div(Ether(), IP()), TCP(options=[("NOP", ""), ("EOL", "")])
        )
        p0f_str = "4:255-:*:*:*,*:nop,eol+2::*"
        self._test_p0f(packet, p0f_str, True)

        # eol+2, should be 4
        packet = old_div(
            old_div(Ether(), IP()), TCP(options=[("NOP", ""), ("EOL", "")])
        )
        p0f_str = "4:255-:*:*:*,*:nop,eol+4::*"
        self._test_p0f(packet, p0f_str, False)

    def test_olayout_ipv6(self):
        # mss, ws, nop, sok, eol
        packet = old_div(
            old_div(Ether(), IPv6()),
            TCP(options=[("MSS", 1000), ("WScale", 1), ("NOP", ""), ("SAckOK", "")]),
        )
        p0f_str = "6:255-:*:*:*,*:mss,ws,nop,sok,eol::*"
        self._test_p0f(packet, p0f_str, True)

        # (mss, ws, nop, sok, eol) should be (mss, nop, sok, eol)
        packet = old_div(
            old_div(Ether(), IPv6()),
            TCP(options=[("MSS", 1000), ("WScale", 1), ("NOP", ""), ("SAckOK", "")]),
        )
        p0f_str = "6:255-:*:*:*,*:mss,nop,sok,eol::*"
        self._test_p0f(packet, p0f_str, False)

    def test_olayout_data_off_ipv6(self):
        # 3, 4 and 5 nops
        packet = old_div(
            old_div(Ether(), IPv6()),
            TCP(
                options=[
                    ("NOP", ""),
                    ("NOP", ""),
                    ("NOP", ""),
                    ("NOP", ""),
                    ("NOP", ""),
                ]
            ),
        )
        p0f_str = "6:255-:*:*:*,*:nop,nop,nop,nop,nop::*"
        self._test_p0f(packet, p0f_str, True)

        packet = old_div(
            old_div(Ether(), IPv6()),
            TCP(options=[("NOP", ""), ("NOP", ""), ("NOP", ""), ("NOP", "")]),
        )
        p0f_str = "6:255-:*:*:*,*:nop,nop,nop,nop::*"
        self._test_p0f(packet, p0f_str, True)

        packet = old_div(
            old_div(Ether(), IPv6()),
            TCP(options=[("NOP", ""), ("NOP", ""), ("NOP", "")]),
        )
        p0f_str = "6:255-:*:*:*,*:nop,nop,nop::*"
        self._test_p0f(packet, p0f_str, True)

    def test_empty_olayout_ipv6(self):
        packet = old_div(old_div(Ether(), IPv6()), TCP())
        p0f_str = "6:255-:*:*:*,*:::*"
        self._test_p0f(packet, p0f_str, True)

        packet = old_div(old_div(Ether(), IPv6()), TCP(options=[("NOP", "")]))
        p0f_str = "6:255-:*:*:*,*:::*"
        self._test_p0f(packet, p0f_str, False)

    def test_eol_ipv6(self):
        # eol (0)
        packet = old_div(
            old_div(Ether(), IPv6()), TCP(options=[("NOP", ""), ("EOL", "")])
        )
        p0f_str = "6:255-:*:*:*,*:nop,eol+0::*"
        self._test_p0f(packet, p0f_str, True)

        # eol (1)
        packet = old_div(
            old_div(Ether(), IPv6()),
            TCP(options=[("NOP", ""), ("NOP", ""), ("EOL", "")]),
        )
        p0f_str = "6:255-:*:*:*,*:nop,nop,eol+1::*"
        self._test_p0f(packet, p0f_str, True)

        # eol+2, should be 4
        packet = old_div(
            old_div(Ether(), IPv6()), TCP(options=[("NOP", ""), ("EOL", "")])
        )
        p0f_str = "6:255-:*:*:*,*:nop,eol+4::*"
        self._test_p0f(packet, p0f_str, False)

    def test_df(self):
        packet = old_div(old_div(Ether(), IP(flags=2)), TCP())
        p0f_str = "4:255-:*:*:*,*::df:*"
        self._test_p0f(packet, p0f_str, True)

        packet = old_div(old_div(Ether(), IP(flags=2, id=4)), TCP())
        p0f_str = "4:255-:*:*:*,*::id+:*"
        self._test_p0f(packet, p0f_str, True)

        # id should be nz
        packet = old_div(old_div(Ether(), IP(flags=2, id=0)), TCP())
        p0f_str = "4:255-:*:*:*,*::id+:*"
        self._test_p0f(packet, p0f_str, False)

        # flags should be nz
        packet = old_div(old_div(Ether(), IP(flags=0, id=4)), TCP())
        p0f_str = "4:255-:*:*:*,*::id+:*"
        self._test_p0f(packet, p0f_str, False)

        packet = old_div(old_div(Ether(), IP(flags=0, id=0)), TCP())
        p0f_str = "4:255-:*:*:*,*::id-:*"
        self._test_p0f(packet, p0f_str, True)

        # flags should be zero
        packet = old_div(old_div(Ether(), IP(flags=2, id=0)), TCP())
        p0f_str = "4:255-:*:*:*,*::id-:*"
        self._test_p0f(packet, p0f_str, False)

        # id should be zero
        packet = old_div(old_div(Ether(), IP(flags=0, id=4)), TCP())
        p0f_str = "4:255-:*:*:*,*::id-:*"
        self._test_p0f(packet, p0f_str, False)

    def test_mbz(self):
        packet = old_div(old_div(Ether(), IP(flags=4)), TCP())
        p0f_str = "4:255-:*:*:*,*::0+:*"
        self._test_p0f(packet, p0f_str, True)

    def test_ecn(self):
        packet = old_div(old_div(Ether(), IP(tos=0xFF)), TCP())
        p0f_str = "4:255-:*:*:*,*::ecn:*"
        self._test_p0f(packet, p0f_str, True)

        packet = old_div(old_div(Ether(), IP()), TCP())
        p0f_str = "4:255-:*:*:*,*::ecn:*"
        self._test_p0f(packet, p0f_str, False)

    def test_seq(self):
        packet = old_div(old_div(Ether(), IP()), TCP())
        p0f_str = "4:255-:*:*:*,*::seq-:*"
        self._test_p0f(packet, p0f_str, True)

        # seq should be zero
        packet = old_div(old_div(Ether(), IP()), TCP(seq=0xCAFE))
        p0f_str = "4:255-:*:*:*,*::seq-:*"
        self._test_p0f(packet, p0f_str, False)

    def test_seq_ipv6(self):
        packet = old_div(old_div(Ether(), IPv6()), TCP())
        p0f_str = "6:255-:*:*:*,*::seq-:*"
        self._test_p0f(packet, p0f_str, True)

        # seq should be zero
        packet = old_div(old_div(Ether(), IPv6()), TCP(seq=0xCAFE))
        p0f_str = "6:255-:*:*:*,*::seq-:*"
        self._test_p0f(packet, p0f_str, False)

    def test_ack(self):
        packet = old_div(old_div(Ether(), IP()), TCP(ack=0xCAFE))
        p0f_str = "4:255-:*:*:*,*::ack+:*"
        self._test_p0f(packet, p0f_str, True)

        # ack should be nz
        p0f_str = "4:255-:*:*:*,*::ack+:*"
        packet = old_div(old_div(Ether(), IP()), TCP())
        self._test_p0f(packet, p0f_str, False)

        packet = old_div(old_div(Ether(), IP()), TCP(flags="A"))
        p0f_str = "4:255-:*:*:*,*::ack-:*"
        self._test_p0f(packet, p0f_str, True)

        # ack flag should be set
        packet = old_div(old_div(Ether(), IP()), TCP())
        p0f_str = "4:255-:*:*:*,*::ack-:*"
        self._test_p0f(packet, p0f_str, False)

    def test_ack_ipv6(self):
        packet = old_div(old_div(Ether(), IPv6()), TCP(ack=0xCAFE))
        p0f_str = "6:255-:*:*:*,*::ack+:*"
        self._test_p0f(packet, p0f_str, True)

        # ack should be nz
        p0f_str = "6:255-:*:*:*,*::ack+:*"
        packet = old_div(old_div(Ether(), IPv6()), TCP())
        self._test_p0f(packet, p0f_str, False)

        packet = old_div(old_div(Ether(), IPv6()), TCP(flags="A"))
        p0f_str = "6:255-:*:*:*,*::ack-:*"
        self._test_p0f(packet, p0f_str, True)

        # ack flag should be set
        packet = old_div(old_div(Ether(), IPv6()), TCP())
        p0f_str = "6:255-:*:*:*,*::ack-:*"
        self._test_p0f(packet, p0f_str, False)

    def test_urg(self):
        packet = old_div(old_div(Ether(), IP()), TCP(urgptr=0xCAFE))
        p0f_str = "4:255-:*:*:*,*::uptr+:*"
        self._test_p0f(packet, p0f_str, True)

        # uptr should be set
        packet = old_div(old_div(Ether(), IP()), TCP())
        p0f_str = "4:255-:*:*:*,*::uptr+:*"
        self._test_p0f(packet, p0f_str, False)

        packet = old_div(old_div(Ether(), IP()), TCP(flags="U"))
        p0f_str = "4:255-:*:*:*,*::urgf+:*"
        self._test_p0f(packet, p0f_str, True)

        # upt flag should be set
        packet = old_div(old_div(Ether(), IP()), TCP())
        p0f_str = "4:255-:*:*:*,*::urgf+:*"
        self._test_p0f(packet, p0f_str, False)

    def test_urg_ipv6(self):
        packet = old_div(old_div(Ether(), IPv6()), TCP(urgptr=0xCAFE))
        p0f_str = "6:255-:*:*:*,*::uptr+:*"
        self._test_p0f(packet, p0f_str, True)

        # uptr should be set
        packet = old_div(old_div(Ether(), IPv6()), TCP())
        p0f_str = "6:255-:*:*:*,*::uptr+:*"
        self._test_p0f(packet, p0f_str, False)

        packet = old_div(old_div(Ether(), IPv6()), TCP(flags="U"))
        p0f_str = "6:255-:*:*:*,*::urgf+:*"
        self._test_p0f(packet, p0f_str, True)

        # upt flag should be set
        packet = old_div(old_div(Ether(), IPv6()), TCP())
        p0f_str = "6:255-:*:*:*,*::urgf+:*"
        self._test_p0f(packet, p0f_str, False)

    def test_push(self):
        packet = old_div(old_div(Ether(), IP()), TCP(flags="P"))
        p0f_str = "4:255-:*:*:*,*::pushf+:*"
        self._test_p0f(packet, p0f_str, True)

        # push flag should be set
        packet = old_div(old_div(Ether(), IP()), TCP())
        p0f_str = "4:255-:*:*:*,*::pushf+:*"
        self._test_p0f(packet, p0f_str, False)

    def test_push_ipv6(self):
        packet = old_div(old_div(Ether(), IPv6()), TCP(flags="P"))
        p0f_str = "6:255-:*:*:*,*::pushf+:*"
        self._test_p0f(packet, p0f_str, True)

        # push flag should be set
        packet = old_div(old_div(Ether(), IPv6()), TCP())
        p0f_str = "6:255-:*:*:*,*::pushf+:*"
        self._test_p0f(packet, p0f_str, False)

    def test_ts(self):
        packet = old_div(old_div(Ether(), IP()), TCP(options=[("Timestamp", (0, 0))]))
        p0f_str = "4:255-:*:*:*,*:ts:ts1-:*"
        self._test_p0f(packet, p0f_str, True)

        # ts1 should be zero
        packet = old_div(old_div(Ether(), IP()), TCP(options=[("Timestamp", (1, 0))]))
        p0f_str = "4:255-:*:*:*,*:ts:ts1-:*"
        self._test_p0f(packet, p0f_str, False)

        packet = old_div(old_div(Ether(), IP()), TCP(options=[("Timestamp", (0, 1))]))
        p0f_str = "4:255-:*:*:*,*:ts:ts2+:*"
        self._test_p0f(packet, p0f_str, True)

        # ts2 should be nz
        packet = old_div(old_div(Ether(), IP()), TCP(options=[("Timestamp", (0, 0))]))
        p0f_str = "4:255-:*:*:*,*:ts:ts2+:*"
        self._test_p0f(packet, p0f_str, False)

    def test_ts_ipv6(self):
        packet = old_div(old_div(Ether(), IPv6()), TCP(options=[("Timestamp", (0, 0))]))
        p0f_str = "6:255-:*:*:*,*:ts:ts1-:*"
        self._test_p0f(packet, p0f_str, True)

        # ts1 should be zero
        packet = old_div(old_div(Ether(), IPv6()), TCP(options=[("Timestamp", (1, 0))]))
        p0f_str = "6:255-:*:*:*,*:ts:ts1-:*"
        self._test_p0f(packet, p0f_str, False)

        packet = old_div(old_div(Ether(), IPv6()), TCP(options=[("Timestamp", (0, 1))]))
        p0f_str = "6:255-:*:*:*,*:ts:ts2+:*"
        self._test_p0f(packet, p0f_str, True)

        # ts2 should be nz
        packet = old_div(old_div(Ether(), IPv6()), TCP(options=[("Timestamp", (0, 0))]))
        p0f_str = "6:255-:*:*:*,*:ts:ts2+:*"
        self._test_p0f(packet, p0f_str, False)

    def test_opt(self):
        packet = old_div(
            old_div(Ether(), IP()),
            TCP(options=[("NOP", ""), ("EOL", ""), ("NOP", ""), ("NOP", "")]),
        )
        p0f_str = "4:255-:*:*:*,*:nop,eol+2:opt+:*"
        self._test_p0f(packet, p0f_str, True)

        # should not be opt+
        packet = old_div(
            old_div(Ether(), IP()), TCP(options=[("NOP", ""), ("EOL", "")])
        )
        p0f_str = "4:255-:*:*:*,*:nop,eol+2:opt+:*"
        self._test_p0f(packet, p0f_str, False)

    def test_opt_ipv6(self):
        packet = old_div(
            old_div(Ether(), IPv6()),
            TCP(options=[("NOP", ""), ("EOL", ""), ("NOP", ""), ("NOP", "")]),
        )
        p0f_str = "6:255-:*:*:*,*:nop,eol+2:opt+:*"
        self._test_p0f(packet, p0f_str, True)

        # should not be opt+
        packet = old_div(
            old_div(Ether(), IPv6()),
            TCP(options=[("NOP", ""), ("NOP", ""), ("EOL", "")]),
        )
        p0f_str = "6:255-:*:*:*,*:nop,nop,eol+1:opt+:*"
        self._test_p0f(packet, p0f_str, False)

    def test_exws(self):
        packet = old_div(old_div(Ether(), IP()), TCP(options=[("WScale", 20)]))
        p0f_str = "4:255-:*:*:*,*:ws:exws:*"
        self._test_p0f(packet, p0f_str, True)

        # ws is not exceeding 14
        packet = old_div(old_div(Ether(), IP()), TCP(options=[("WScale", 1)]))
        p0f_str = "4:255-:*:*:*,*:ws:exws:*"
        self._test_p0f(packet, p0f_str, False)

    def test_exws_ipv6(self):
        packet = old_div(old_div(Ether(), IPv6()), TCP(options=[("WScale", 20)]))
        p0f_str = "6:255-:*:*:*,*:ws:exws:*"
        self._test_p0f(packet, p0f_str, True)

        # ws is not exceeding 14
        packet = old_div(old_div(Ether(), IPv6()), TCP(options=[("WScale", 1)]))
        p0f_str = "6:255-:*:*:*,*:ws:exws:*"
        self._test_p0f(packet, p0f_str, False)

    def test_linux(self):
        packet = old_div(
            old_div(Ether(), IP(id=0x1111)),
            TCP(seq=0xABCDAAAA, options=[("Timestamp", (0xDCBABBBB, 0))]),
        )
        p0f_str = "4:255-:*:*:*,*:ts:linux:*"
        self._test_p0f(packet, p0f_str, True)

        packet = old_div(
            old_div(Ether(), IP(id=0xCAFE)),
            TCP(seq=0xABCDAAAA, options=[("Timestamp", (0xDCBABBBB, 0))]),
        )
        p0f_str = "4:255-:*:*:*,*:ts:linux:*"
        self._test_p0f(packet, p0f_str, False)

    def test_bad(self):
        packet = old_div(
            old_div(Ether(), IP()), TCP(options=[("NOP", ""), (1, 1), (2, 2)])
        )
        p0f_str = "4:255-:*:*:*,*:nop:bad:*"
        self._test_p0f(packet, p0f_str, True)

    def test_pclass(self):
        packet = old_div(old_div(Ether(), IP()), TCP())
        p0f_str = "4:255-:*:*:*,*:::0"
        self._test_p0f(packet, p0f_str, True)

        # payload len should be nz
        packet = old_div(old_div(Ether(), IP()), TCP())
        p0f_str = "4:255-:*:*:*,*:::+"
        self._test_p0f(packet, p0f_str, False)

        packet = old_div(old_div(old_div(Ether(), IP()), TCP()), Raw("data"))
        p0f_str = "4:255-:*:*:*,*:::+"
        self._test_p0f(packet, p0f_str, True)

        # payload len should be zero
        packet = old_div(old_div(old_div(Ether(), IP()), TCP()), Raw("data"))
        p0f_str = "4:255-:*:*:*,*:::0"
        self._test_p0f(packet, p0f_str, False)

    def test_pclass_ipv6(self):
        packet = old_div(old_div(Ether(), IPv6()), TCP())
        p0f_str = "6:255-:*:*:*,*:::0"
        self._test_p0f(packet, p0f_str, True)

        # payload len should be nz
        packet = old_div(old_div(Ether(), IPv6()), TCP())
        p0f_str = "6:255-:*:*:*,*:::+"
        self._test_p0f(packet, p0f_str, False)

        packet = old_div(old_div(old_div(Ether(), IPv6()), TCP()), Raw("data"))
        p0f_str = "6:255-:*:*:*,*:::+"
        self._test_p0f(packet, p0f_str, True)

        # payload len should be zero
        packet = old_div(old_div(old_div(Ether(), IPv6()), TCP()), Raw("data"))
        p0f_str = "6:255-:*:*:*,*:::0"
        self._test_p0f(packet, p0f_str, False)

    def test_invalid_signature(self):
        packet = old_div(old_div(Ether(), IPv6()), TCP())

        with self.assertRaises(ValueError):
            p0f_str = "*:255-:*:*:*,*:::0"
            self._test_p0f(packet, p0f_str, False)

        with self.assertRaises(ValueError):
            p0f_str = "22:255-:*:*:*,*:::0"
            self._test_p0f(packet, p0f_str, False)

        with self.assertRaises(ValueError):
            p0f_str = "4:x:*:*:*,*:::0"
            self._test_p0f(packet, p0f_str, False)

        with self.assertRaises(ValueError):
            p0f_str = "4:255x:*:*:*,*:::0"
            self._test_p0f(packet, p0f_str, False)

        with self.assertRaises(ValueError):
            p0f_str = "4:64:0.1:*:*,*:::0"
            self._test_p0f(packet, p0f_str, False)

        with self.assertRaises(ValueError):
            p0f_str = "4:64:*:y:*,*:::0"
            self._test_p0f(packet, p0f_str, False)

        with self.assertRaises(ValueError):
            p0f_str = "4:64:*:*:nope*2,*:::0"
            self._test_p0f(packet, p0f_str, False)

        with self.assertRaises(ValueError):
            p0f_str = "4:64:*:*:mss*2,x:::0"
            self._test_p0f(packet, p0f_str, False)

        with self.assertRaises(ValueError):
            p0f_str = "4:64:*:*:*,*:mss,nop,nope::0"
            self._test_p0f(packet, p0f_str, False)

        with self.assertRaises(ValueError):
            p0f_str = "4:64:*:*:*,*::quirk:0"
            self._test_p0f(packet, p0f_str, False)

        with self.assertRaises(ValueError):
            p0f_str = "4:64:*:*:*,*:::-"
            self._test_p0f(packet, p0f_str, False)


if __name__ == "__main__":
    unittest.main()
