import re
import math

ip = {
    'hl':   '(ip[0] & 0xf)',
    'ecn':  '(ip[1] & 0x2)',
    'tl':   'ip[2:2]',
    'ipid': 'ip[4:2]',
    'df':   '(ip[6] & 0x40)',
    'zero': '(ip[6] & 0x80)',
    'ttl':  'ip[8]',
}

ip6 = {
    'pl':  '(ip6[4:2])',
    'ttl': '(ip6[7])',
    'flow': '(ip6[2:2])',
}

tcp = {
    'win_size': 'tcp[14:2]',
    'data_off': '(tcp[12] >> 4)',
    'seq':      'tcp[4:4]',
    'ack_flag': '(tcp[tcpflags] & tcp-ack)',
    'ack':      'tcp[8:4]',
    'urg_flag': '(tcp[tcpflags] & tcp-urg)',
    'urg':      'tcp[18:2]',
    'push_flag': '(tcp[tcpflags] & tcp-push)',
}

tcp6 = {
    'win_size': 'ip6[(40 + 14):2]',
    'data_off': '(ip6[40 + 12] >> 4)',
    'seq':      'ip6[(40 + 4):4]',
    'ack_flag': '(ip6[40 + tcpflags] & tcp-ack)',
    'ack':      'ip6[(40 + 8):4]',
    'urg_flag': '(ip6[40 + tcpflags] & tcp-urg)',
    'urg':      'ip6[(40 + 18):2]',
    'push_flag': '(ip6[40 + tcpflags] & tcp-push)',
}

class P0fBPF:
    def __init__(self, p0f_str):
        self.p0f_str = p0f_str

        self.parse_sig()
        self.build_abstract_desc()
        self.build_bpf_filter()
        self.build_doc_bpf_filter()

    def parse_ittl(self):
        if self.ittl.endswith("-"):
            self.ttl_rand = True
        else:
            self.ttl_rand = False

    def parse_win_size(self):
        m = re.match("mss\*(?P<mss>(\d+))", self.win_size)
        if m:
            self.win_size_type = 'mss_mult'
            self.win_size = m.groupdict()['mss']
        else:
            m = re.match("mtu\*(?P<mtu>(\d+))", self.win_size)
            if m:
                self.win_size_type = 'mtu_mult'
                self.win_size = m.groupdict()['mtu']
            else:
                m = re.match("%(?P<const>(\d+))", self.win_size)
                if m:
                    self.win_size_type = 'const_mult'
                    self.win_size = m.groupdict()['const']
                else:
                    self.win_size_type = 'const'

    def parse_sig(self):
        self.ver, self.ittl, self.olen, self.mss, self.win, self.olayout, self.quirks, self.pclass = self.p0f_str.split(':')

        if self.ver != '4' and self.ver != '6':
            raise ValueError("IP version must be either 4 or 6")

        if not re.match("^(\d+)-?$", self.ittl):
            raise ValueError("Invalid ttl field")
        self.parse_ittl()

        if self.olen != '*' and not self.olen.isdigit():
            raise ValueError("Invalid option len field")

        if self.mss != '*' and not self.mss.isdigit():
            raise ValueError("Invalid mss field")

        self.win_size, self.win_scale = self.win.split(',')
        if self.win_size != "*" and not re.match("^((mss\*)|(mtu\*)|(%))?(\d+)$", self.win_size):
            raise ValueError("Invalid win size field")
        self.parse_win_size()

        if self.win_scale != '*' and not self.win_scale.isdigit():
            raise ValueError("Invalid win size field")

        self.olayout = self.olayout.split(',')
        if self.olayout == ['']: self.olayout = []
        opts = set(self.olayout) - set(['eol', 'nop', 'mss', 'ws', 'sok', 'ts'])
        if len(opts) == 1 and not re.match("^eol\+(\d+)$", opts.pop()):
                raise ValueError("Invalid option in olayout")
        elif len(opts) >= 1:
                raise ValueError("Invalid options in olayout")

        self.quirks = self.quirks.split(',')
        quirks = set(self.quirks) - set(['', 'df', 'id+', 'id-', 'ecn', '0+', 'flow', 'seq-', 'ack-', 'ack+', 'uptr+', 'urgf+', 'pushf+', 'ts1-', 'ts2+', 'opt+', 'exws', 'linux', 'bad'])
        if len(quirks) > 0:
            raise ValueError("Invalid quirks")

        if not re.match("0|\+|\*", self.pclass):
            raise ValueError("Invalid pclass")

    def ip_field(self, field):
        return ip[field] if self.ver == '4' else ip6[field]

    def tcp_field(self, field):
        return tcp[field] if self.ver == '4' else tcp6[field]

    def get_tcp_opt_offset(self, opts, opt, off, len):
        for o in opts:
            if o[0] == opt:
                if self.ver == '4':
                    return ("tcp[%d:%d]" % (o[2] + off, len))
                else:
                    return ("ip6[(40 + %d):%d]" % (o[2] + off, len))
        raise ValueError("Requested TCP option is not in olayout")

    def build_tcp_opt_table(self):
        self.tcp_opt_offsets = []
        self.eol_start = 0
        self.eol_pad = 0
        self.tcp_opt_len = 0
        cur_tcp_opt_off = 20

        for opt in self.olayout:
            if   opt == 'eol': code, inc = 0, 1
            elif opt == 'nop': code, inc = 1, 1
            elif opt == 'mss': code, inc = 2, 4
            elif opt == 'ws':  code, inc = 3, 3
            elif opt == 'sok': code, inc = 4, 2
            elif opt == 'ts':  code, inc = 8, 10
            else:
                m = re.match("eol\+(?P<eol_pad>(\d+))", opt)
                if m:
                    self.eol_pad = int(m.groupdict()['eol_pad'])
                    opt = 'eol'
                    code = 0
                    inc = 1
                else:
                    raise ValueError("Invalid TCP option in olayout field")

            self.tcp_opt_offsets.append([opt, code, cur_tcp_opt_off])
            cur_tcp_opt_off += inc
            self.eol_start = cur_tcp_opt_off

        self.tcp_opt_len = cur_tcp_opt_off + self.eol_pad - 20

    def build_ipver(self):
        ver = 'ip' if self.ver == '4' else 'ip6'
        self.steps.append([ver, 'ip version'])

    def build_ttl(self):
        if self.ttl_rand == False:
            ttl = self.ip_field('ttl')
            ittl = int(self.ittl)

            self.steps.append([ttl, '<=', ittl, 'ttl <= %d' % ittl])
            if ittl > 32:
                self.steps.append([ttl, '>', ittl - 35, 'ttl > %d' % (ittl - 35)])

    def build_olen(self):
        if self.ver == '4' and self.olen != '*':
            hl = self.ip_field('hl')
            self.steps.append([hl, '==', 5 + int(self.olen), 'IP options len == %s' % self.olen])

    def build_mss(self):
        if self.mss != '*' and self.mss != '0':
            mss_off = self.get_tcp_opt_offset(self.tcp_opt_offsets, 'mss', 2, 2)
            self.steps.append([mss_off, '==', self.mss, 'mss == %s' % self.mss])

    def build_win_size(self):
        if self.win_size != '*':
            win_size = self.tcp_field('win_size')

            if self.win_size_type == 'mss_mult':
                mss_off = self.get_tcp_opt_offset(self.tcp_opt_offsets, 'mss', 2, 2)
                mss_mult = [mss_off, '*', self.win_size]
                self.steps.append([win_size, '==', mss_mult, 'win size == mss * %s' % self.win_size])
            elif self.win_size_type == 'mtu_mult':
                mtu_mult = ['1500', '*', self.win_size] # assume mtu=1500
                self.steps.append([win_size, '==', mtu_mult, 'win size == mtu'])
            elif self.win_size_type == 'const_mult':
                const_mul = [win_size, '%', self.win_size]
                self.steps.append([const_mul, '==', 0, 'win size == x * %s' % self.win_size])
            else:
                self.steps.append([win_size, '==', self.win_size, 'win size == %s' % self.win_size])

    def build_win_scale(self):
        if self.win_scale != '*' and self.win_scale != '0':
            ws_off = self.get_tcp_opt_offset(self.tcp_opt_offsets, 'ws', 2, 1)
            self.steps.append([ws_off, '==', self.win_scale, 'win scale == %s' % self.win_scale])

    def build_eol_pad(self):
        pad_pos = self.eol_start
        pad_left = self.eol_pad

        while pad_left > 0:
            if (self.eol_pad >= 4):
                cur_chunk_len = 4
            elif (self.eol_pad >= 2):
                cur_chunk_len = 2
            else:
                cur_chunk_len = 1

            op = '!=' if 'opt+' in self.quirks else '=='

            if self.ver == '4':
                self.steps.append(["tcp[%s:%s]" % (pad_pos, cur_chunk_len), op, 0, 'eol pad %s 0' % op])
            else:
                self.steps.append(["ip6[(40 + %s):%s]" % (pad_pos, cur_chunk_len), op, 0, 'eol pad %s 0' % op])

            pad_pos += cur_chunk_len
            pad_left -= cur_chunk_len

    def build_tcp_olayout(self):
        if not 'bad' in self.quirks:
            data_off = self.tcp_field('data_off')
            data_off_val = 5 + int(math.ceil(self.tcp_opt_len / 4.0))
            self.steps.append([data_off, '==', data_off_val, 'TCP data offset'])

        for o in self.tcp_opt_offsets:
            if self.ver == '4':
                o_off = "tcp[%d]" % o[2]
            else:
                o_off = "ip6[40 + %d]" % (o[2])
            self.steps.append([o_off, '==', o[1], "olayout " + o[0]])

        self.build_eol_pad()

    def build_df(self):
        if self.ver == '4':
            df = self.ip_field('df')
            id = self.ip_field('ipid')

            if 'df' in self.quirks:
                self.steps.append([df, '!=', 0, 'df set'])
            elif 'id+' in self.quirks:
                self.steps.append([df, '!=', 0, 'id+ (df set)'])
                self.steps.append([id, '!=', 0, 'id+ (id set) '])
            elif 'id-' in self.quirks:
                self.steps.append([df, '==', 0, 'id- (df not set)'])
                self.steps.append([id, '==', 0, 'id- (id not set)'])

    def build_ecn(self):
        if self.ver == '4' and 'ecn' in self.quirks:
            ecn = self.ip_field('ecn')
            self.steps.append([ecn, '!=', 0, 'ecn'])

    def build_zero(self):
        if self.ver == '4':
            zero = self.ip_field('zero')
            if '0+' in self.quirks:
                self.steps.append([zero, '!=', 0, 'mbz non zero'])
            else:
                self.steps.append([zero, '==', 0, 'mbz zero'])

    def build_flow(self):
        if self.ver == '6' and 'flow' in self.quirks:
            flow = self.ip_field('flow')
            self.steps.append([flow, '!=', 0, 'flow'])

    def build_seq(self):
        if 'seq-' in self.quirks:
            seq = self.tcp_field('seq')
            self.steps.append([seq, '==', 0, 'seq- (seq num not set)'])

    def build_ack(self):
        ack_flag = self.tcp_field('ack_flag')
        ack = self.tcp_field('ack')
        if 'ack+' in self.quirks:
            self.steps.append([ack_flag, '==', 0, 'ack+ (ack flag not set)'])
            self.steps.append([ack, '!=', 0, 'ack+ (ack num set)'])
        elif 'ack-' in self.quirks:
            self.steps.append([ack_flag, '!=', 0, 'ack- (ack flag set)'])
            self.steps.append([ack, '==', 0, 'ack- (ack num not set)'])

    def build_urg(self):
        urg_flag = self.tcp_field('urg_flag')
        urg = self.tcp_field('urg')

        if 'uptr+' in self.quirks:
            self.steps.append([urg_flag, '==', 0, 'uptr+ (urg flag not set)'])
            self.steps.append([urg, '!=', 0, 'uptr+ (urg ptr set)'])
        elif 'urgf+' in self.quirks:
            self.steps.append([urg_flag, '!=', 0, 'urgf+ (urg flag set)'])

    def build_push(self):
        if 'pushf+' in self.quirks:
            push_flag = self.tcp_field('push_flag')
            self.steps.append([push_flag, '!=', 0, 'pushf+ (psh flag set)'])

    def build_ts(self):
        if 'ts1-' in self.quirks:
            ts_off = self.get_tcp_opt_offset(self.tcp_opt_offsets, 'ts', 2, 4)
            self.steps.append([ts_off, '==', 0, 'ts1- (ts1 not set)'])

        if 'ts2+' in self.quirks:
            ts_off = self.get_tcp_opt_offset(self.tcp_opt_offsets, 'ts', 6, 4)
            self.steps.append([ts_off, '!=', 0, 'ts2+ (ts2 set)'])

    def build_exws(self):
        if 'exws' in self.quirks:
            ws_off = self.get_tcp_opt_offset(self.tcp_opt_offsets, 'ws', 2, 1)
            self.steps.append([ws_off, '>', 14, 'exws'])

    def build_linux(self):
        if 'linux' in self.quirks:
            if self.ver == '4':
                seq = self.tcp_field('seq')
                ts = self.get_tcp_opt_offset(self.tcp_opt_offsets, 'ts', 2, 4)
                id = self.ip_field('ipid')

                seq_xor_ts = [seq, '^', ts]
                seq_xor_ts = [seq_xor_ts, '&', '0xffff']

                self.steps.append([id, '==', seq_xor_ts, 'linux'])

    def build_quirks(self):
        self.build_df()
        self.build_ecn()
        self.build_zero()
        self.build_flow()
        self.build_seq()
        self.build_ack()
        self.build_urg()
        self.build_push()
        self.build_ts()
        self.build_exws()
        self.build_linux()

    def build_pclass(self):
        if self.pclass != '*':
            if self.ver == '4':
                tl = self.ip_field('tl')
                hl = self.ip_field('hl')
                data_off = self.tcp_field('data_off')
                payload_len = "(%s - (%s * 4) - (%s * 4))" % (tl, hl, data_off)
            else:
                pl = self.ip_field('pl')
                data_off = self.tcp_field('data_off')
                payload_len = "(%s - (%s * 4))" % (pl, data_off)
            op = '==' if self.pclass == '0' else '!='
            self.steps.append([payload_len, op, 0, 'payload len %s 0' % op])

    def build_abstract_desc(self):
        self.steps = []

        self.build_tcp_opt_table()
        self.build_ipver()
        self.build_ttl()
        self.build_olen()
        self.build_mss()
        self.build_win_size()
        self.build_win_scale()
        self.build_tcp_olayout()
        self.build_quirks()
        self.build_pclass()

    def expand_step(self, s, doc=False):
        if not isinstance(s, list):
            return s
        elif len(s) == 2:
            if doc:
                return "%s: %s" % (s[0], s[1])
            else:
                return "%s" % s[0]
        else:
            lhs = self.expand_step(s[0])
            rhs = self.expand_step(s[2])
            if doc:
                return "(%s %s %s): %s" % (lhs, s[1], rhs, s[3])
            else:
                return "(%s %s %s)" % (lhs, s[1], rhs)

    def build_bpf_filter(self):
        self.bpf_str = " and ".join(self.expand_step(s) for s in self.steps)

    def build_doc_bpf_filter(self):
        self.doc_bpf_str = "\n".join(self.expand_step(s, True) for s in self.steps)
