Floodgate
=========

Here you can find a set of tool for analyzing and processing of pcap
traffic dumps. The aim of this tool is to help creating a BPF rule
that will match (and drop) malicious traffic.

To run these scripts you will need:

 - kernel 3.10+ (we need a decent <linux/netfilter.h> header)
 - sudo easy-install pcappy
 - sudo apt-get install binutils-dev libreadline-dev python-scapy


iptables_bpf.py
===============

This script generates a simple bash script that contains iptables
rules that drop traffic based on selected parameters.

For example, to generate a script dropping packets exactly to a domain
"example.com" you can run:

    $ ./iptables_bpf.py dns example.com
    Generated file 'bpf_dns_ip4_example_com.sh'

If you want the ip6tables commands for IPv6 use --inet6 option:

    $ ./iptables_bpf.py --inet6 dns example.com
    Generated file 'bpf_dns_ip6_example_com.sh'

The rule can match any from a number listed domains:

    $ ./iptables_bpf.py dns example.com example1.com example2.com
    Generated file 'bpf_dns_ip4_example_com_example1_com_example2_com.sh'

If you want to match any subdomain you can use a star '*'. This will
only work if star is the only character in a domain part. Valid
examples:

    $ ./iptables_bpf.py dns *.example.com
    Generated file 'bpf_dns_ip4_any_example_com.sh'

    $ ./iptables_bpf.py dns *.example.*.gov.de
    Generated file 'bpf_dns_ip4_any_example_any_gov_de.sh'


You can run the generated script to apply the rule and match it
against flooded ip address:

    $ sudo ./bpf_dns_ip4_example_com.sh 1.2.3.4/32

You need bpf-compatible IPTABLES, you can override the default path:

    $ sudo IPTABLES=~/iptables ./bpf_dns_ip4_example_com.sh 1.2.3.4/32

To remove the iptable rule simply specify --delete:

    $ sudo ./bpf_dns_ip4_example_com.sh --delete
