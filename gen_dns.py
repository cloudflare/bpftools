import string
import subprocess


class X: pass

def generate(parameters, inet=None, l3off=None):
    cmd = ['./bpf_dns.py']
    if inet is not None and inet != 4:
        cmd.append('-%s' % inet)
    if l3off is not None:
        cmd.append('-o%s' % l3off)
    r = X()
    r.bytecode = subprocess.check_output(cmd + parameters)
    r.assembly = subprocess.check_output(cmd + ['-s'] + parameters)
    r.cmd = repr([cmd[0][2:]] + cmd[1:] + parameters)

    name_parts = []
    for domain in parameters:
        if domain[0] == '-':
            continue

        domain = domain.strip(".").strip()
        parts = []
        for part in domain.split("."):
            if part == '*':
                parts.append( 'any' )
            else:
                parts.append( ''.join(c if c in string.printable and c not in string.whitespace+string.punctuation else 'x'
                                      for c in part) )
        name_parts.append( '_'.join(parts) )
    r.name = '_'.join(name_parts)

    r.bytecode = r.bytecode.strip()
    return r

