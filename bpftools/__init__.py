import StringIO as stringio
import os
import sys

from . import gen_dns
from . import gen_dns_validate
from . import gen_suffix
from . import utils
from . import gen_badrand
from . import gen_tcpsyn_data

name_to_gen = {
    'dns': gen_dns.gen,
    'dns_validate': gen_dns_validate.gen,
    'suffix': gen_suffix.gen,
    'badrand': gen_badrand.gen,
    'tcpsyn_data': gen_tcpsyn_data.gen,
    }

generator_names = name_to_gen.keys()


def gen(typename, params, **kwargs):
    gentype = name_to_gen[typename]

    assembly = kwargs.get('assembly', False)
    del kwargs['assembly']

    sys.stdout, saved_stdout = stringio.StringIO(), sys.stdout
    def new_exit(s):
        sys.stdout.seek(0)
        data = sys.stdout.read()
        sys.stdout = saved_stdout
        print data
        os._exit(s)
    sys.exit, saved_exit = new_exit, sys.exit

    name = gentype(params, **kwargs)

    data = sys.stdout.seek(0)
    data = sys.stdout.read()
    sys.stdout = saved_stdout
    sys.exit = saved_exit

    if assembly:
        return name, data
    return name, utils.bpf_compile(data)
