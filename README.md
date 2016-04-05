Nat-Extractor

usage: python extr-nat.py input_file output_file

Dependencies: netaddr

Summary: Parse out named objects and NAT tables from a Cisco firewall configuration file. 

TODO:
1. Deal with service objects
2. For ranges:
	a. resolve named objects
	b. make entire range explicit
3. Make it parse out NAT tables
4. Separate main and functions into different files
5. Make it so that no output file is required to run the program