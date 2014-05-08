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
