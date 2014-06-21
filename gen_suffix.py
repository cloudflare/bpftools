import string
import subprocess


class X: pass

def generate(parameters, inet=None, l3off=None):
    cmd = ['./bpf_suffix.py']
    r = X()
    r.bytecode = subprocess.check_output(cmd + parameters)
    r.assembly = subprocess.check_output(cmd + ['-s'] + parameters)
    r.cmd = repr([cmd[0][2:]] + cmd[1:] + parameters)

    r.name = '_'.join(parameters)

    r.bytecode = r.bytecode.strip()
    return r

