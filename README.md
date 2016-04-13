Nat-Extractor

usage: python extr-nat.py [options] config_file

Dependencies: netaddr, argparse

Summary: Parse out named objects and NAT tables from a Cisco firewall configuration file. 

TODO:
1. clean up code
2. add different output options (txt, csv, etc)
3. make name_to_ip() work on keys as well as values
4. make it so you can specify a single object to define