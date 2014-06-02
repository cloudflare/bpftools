import string
import subprocess


class X: pass

def generate(parameters, inet=None, l3off=None):
    cmd = ['./bpf_dns_validate.py']
    if inet is not None and inet != 4:
        cmd.append('-%s' % inet)
    if l3off is not None:
        cmd.append('-o%s' % l3off)
    r = X()
    r.bytecode = subprocess.check_output(cmd + parameters)
    r.assembly = subprocess.check_output(cmd + ['-s'] + parameters)
    r.cmd = repr([cmd[0][2:]] + cmd[1:] + parameters)
    r.name = ''
    r.bytecode = r.bytecode.strip()
    return r

