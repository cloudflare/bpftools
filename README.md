BPF Tools
=========

Here you can find a set of tool for analyzing and processing of pcap
traffic dumps. The aim of this tool is to help creating a BPF rule
that will match (and drop) malicious traffic.

To run these scripts you will need:

 - Kernel headers (ideally from a 3.10+ kernel):

        $ sudo apt-get install linux-headers-generic

 - Installed the dependencies:

        $ sudo apt-get install python-setuptools libpcap-dev libreadline-dev
        $ sudo easy_install pcappy

 - Build the binary tools in `linux_tools` directory:

        $ make


iptables_bpf
============

This script generates a simple bash script that contains iptables
rules that drop traffic based on selected parameters.

For example, to generate a script dropping packets exactly to a domain
"example.com" you can run:

    $ ./iptables_bpf dns -- example.com
    Generated file 'bpf_dns_ip4_example_com.sh'

If you want the ip6tables commands for IPv6 use `-6` option:

    $ ./iptables_bpf -6 dns -- example.com
    Generated file 'bpf_dns_ip6_example_com.sh'

The rule can match any from a number listed domains:

    $ ./iptables_bpf dns -- example.com example1.com example2.com
    Generated file 'bpf_dns_ip4_example_com_example1_com_example2_com.sh'

If you want to match any subdomain you can use a star '*'. This will
only work if star is the only character in a domain part. Valid
examples:

    $ ./iptables_bpf dns -- *.example.com
    Generated file 'bpf_dns_ip4_any_example_com.sh'

    $ ./iptables_bpf dns -- *.example.*.gov.de
    Generated file 'bpf_dns_ip4_any_example_any_gov_de.sh'


You can run the generated script to apply the rule and match it
against one or more flooded ip addresses:

    $ sudo ./bpf_dns_ip4_example_com.sh 1.2.3.4/32

To remove the iptable rule simply specify `--delete`:

    $ sudo ./bpf_dns_ip4_example_com.sh --delete
