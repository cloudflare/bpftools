import os
import setuptools
import shutil
import sys


if not os.path.exists('bpftools/bpf_asm'):
    os.system("make -C linux_tools")
    if not os.path.exists('linux_tools/bpf_asm'):
        print >> sys.stderr, "Type 'make' before packaigng"
        sys.exit(-1)
    shutil.copy('linux_tools/bpf_asm', 'bpftools')


setuptools.setup(
    name='bpftools',
    version='1.0',
    description='BPF Tools - packet analyst toolkit',
    url='https://github.com/cloudflare/bpftools',
    packages=['bpftools'],
    maintainer="Marek Majkowski",
    maintainer_email="marek@cloudflare.com",
    package_data = {
        '': ['bpf_asm'],
        },
    zip_safe = False,
    )
