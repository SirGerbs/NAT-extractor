Nat-Extractor

Summary: Parse out named objects and NAT tables from a Cisco firewall configuration file. 

Dependencies: argparse

usage: extr_nat.py [-h] [-i] [-o] [-n] [-c] config_file

positional arguments:
  config_file   Cisco Firewall Configuration File

optional arguments:
  -h, --help    show this help message and exit
  -i, --ip      convert all named objects to IP addresses
  -o, --object  parses out named objects
  -n, --nat     parses out NAT tables
  -c, --cidr    display subnets in CIDR notation

TODO:
1. clean up code
2. add different output options (txt, csv, etc)
3. make it so you can specify a single object to define
