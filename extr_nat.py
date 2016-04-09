import io
import re
import sys
import netaddr
import argparse

#globally accessible dict to hold network objects
file_dict = {}
ip_dict = {}
nat_dict = {}

#verify user entered enough cmd line arguments
def check_args():
	#print "in check_args"
	
	if len(sys.argv) < 2:
		print "Usage: python extr_nat.py configuration_file"
		exit(1)
	
	return 0
	
#prepopulate ip_dict with known port aliases
def prepop_dict():
	#print "in prepop_dict"
	
	ip_dict["ah"] = "51"
	ip_dict["eigrp"] = "88"
	ip_dict["esp"] = "50"
	ip_dict["gre"] = "47"
	ip_dict["icmp"] = "1"
	ip_dict["icmp6"] = "58"
	ip_dict["igmp"] = "2"
	ip_dict["igrp"] = "9"
	ip_dict["ip"] = "0"
	ip_dict["ipinip"] = "4"
	ip_dict["ipsec"] = "50"
	ip_dict["nos"] = "90"
	ip_dict["ospf"] = "89"
	ip_dict["pcp"] = "108"
	ip_dict["pim"] = "103"
	ip_dict["pptp"] = "47"
	ip_dict["snp"] = "109"
	ip_dict["tcp"] = "6"
	ip_dict["udp"] = "17"
	ip_dict["aol"] = "5190"
	ip_dict["bgp"] = "179"
	ip_dict["biff"] = "512"
	ip_dict["bootpc"] = "68"
	ip_dict["bootps"] = "67"
	ip_dict["chargen"] = "19"
	ip_dict["citrix-ica"] = "1494"
	ip_dict["cmd"] = "514"
	ip_dict["etiqbe"] = "2748"
	ip_dict["daytime"] = "13"
	ip_dict["discard"] = "9"
	ip_dict["domain"] = "53"
	ip_dict["dnsix"] = "195"
	ip_dict["echo"] = "7"
	ip_dict["exec"] = "512"
	ip_dict["finger"] = "79"
	ip_dict["ftp"] = "21"
	ip_dict["ftp-data"] = "20"
	ip_dict["gopher"] = "70"
	ip_dict["https"] = "443"
	ip_dict["h323"] = "1720"
	ip_dict["hostname"] = "101"
	ip_dict["ident"] = "113"
	ip_dict["imap4"] = "143"
	ip_dict["irc"] = "194"
	ip_dict["isakmp"] = "500"
	ip_dict["kerberos"] = "750"
	ip_dict["klogin"] = "543"
	ip_dict["kshell"] = "544"
	ip_dict["ldap"] = "389"
	ip_dict["ldaps"] = "636"
	ip_dict["lpd"] = "515"
	ip_dict["login"] = "513"
	ip_dict["lotusnotes"] = "1352"
	ip_dict["mobile-ip"] = "434"
	ip_dict["nameserver"] = "42"
	ip_dict["netbios-ns"] = "137"
	ip_dict["netbios-dgm"] = "138"
	ip_dict["netbios-ssn"] = "139"
	ip_dict["nntp"] = "119"
	ip_dict["ntp"] = "123"
	ip_dict["pcanywhere-status"] = "5632"
	ip_dict["pcanywhere-data"] = "5631"
	ip_dict["pim-auto-rp"] = "496"
	ip_dict["pop2"] = "109"
	ip_dict["pop3"] = "110"
	ip_dict["pptp"] = "1723"
	ip_dict["radius"] = "1645"
	ip_dict["radius-acct"] = "1646"
	ip_dict["rip"] = "520"
	ip_dict["secureid-udp"] = "5510"
	ip_dict["smtp"] = "25"
	ip_dict["snmp"] = "161"
	ip_dict["snmptrap"] = "162"
	ip_dict["sqlnet"] = "1521"
	ip_dict["ssh"] = "22"
	ip_dict["sunrpc"] = "111"
	ip_dict["syslog"] = "514"
	ip_dict["rpc"] = "111"
	ip_dict["tacacs"] = "49"
	ip_dict["talk"] = "517"
	ip_dict["telnet"] = "23"
	ip_dict["tftp"] = "69"
	ip_dict["time"] = "37"
	ip_dict["uucp"] = "540"
	ip_dict["who"] = "513"
	ip_dict["whois"] = "43"
	ip_dict["www"] = "80"
	ip_dict["xmdcp"] = "177"
	ip_dict["nfs"] = "2049"
	ip_dict["sip"] = "5060"
	ip_dict["rtsp"] = "554"
	
	return 0
	
#function meant to store config file lines in dict, so that no "intermediate" file needs to be used
def file_to_dict(config_file):
	#print "in file_to_dict"
	line_counter = 0
	with open(config_file, "r") as file:
		for line in file:
			#if the line is empty, ignore it
			if re.match(r'^\s*$', line):
				continue
				
			#if the line has "<--- More --->", remove it
			if re.match(r'.*?<--- More --->.*?', line):
				line = re.sub("<--- More --->\s*","",line)
				
			#if the line contains a description, ignore it
			if re.match(r"^\s?description",line):
				continue
			
			file_dict[line_counter] = line
			line_counter += 1
	iter_counter = 0
	
	return 0

#primitive netmask to CIDR conversion. takes result from re.match as argument
def mask_to_cidr2(netmask):
	#print "in mask_to_cidr2"
	
	#obtain the part of netmask we're interested in and remove unwanted whitespace at the beginning of the line
	mask = netmask.group(0)
	mask = re.sub("^\s", "", mask)
	
	#if the string is not in the format of a netmask
	if not re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", mask):
		print mask + " is not a netmask"
		exit(1)
	
	#if string is a netmask find the four octets and convert them to binary
	else:
		octets = re.findall(r"\d{1,3}", mask)
		binary = format(int(octets[0]), "b") + format(int(octets[1]), "b") + format(int(octets[2]), "b") + format(int(octets[3]), "b")
	
	#return the number of 1's that appear in the binary form of the octets
	return "/" + str(binary.count("1"))

#Extract network objects into ip_dict
def extract_network_objects():
	#print "in extract_network_objects"
	
	#object variable to store named objects
	object = ""
	
	#go through the file_dict one line at a time
	iter_counter = 0
	while iter_counter < len(file_dict):
		line = file_dict[iter_counter]
		
		#take out newline at the end
		line = re.sub(r"\s$","",line)

		#if the line declares a range, swap out the space for a dash
		if re.match(r".*range \d+ \d+$", line):
			line = re.sub(r"(?P<one>range \d+) (?P<two>[^\s]+)$", r"\g<one>-\g<two>", line)
		
		#if the line declares a new object
		if re.match("\s?object (network |service ).*", line):
			#print line
			object_group = re.search(r"(^\s?object (network |service ))(?P<this>[^\s]+)$", line)
			object = object_group.group("this")
			
		#regex matches "host <IP>"
		elif re.match(r'\s?host \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line):
			#extract IP address belonging to object				
			ip_group = re.search(r'(\s?host )(?P<this>[^\s]+)$', line)
			ip = ip_group.group("this")
			
			#add network object and ip to dict
			ip_dict[object] = ip
			#print "1" + object + ip
		
		#regex matches "range <IP>-<IP>"
		elif re.match(r'\s?range \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line):
			range = re.search(r".*range (?P<this>[^\s]+)$", line)
			
			#add network object and ip to dict
			ip_dict[object] = range.group("this")
			#print "2" + object + range.group("this")
		#line declares a subnet
		elif re.match(r"\s?subnet\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line):
			#print "i found a subnet"
			subnet = re.search(r"(\s?subnet )(?P<this>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", line)
			
			#add network object and ip to dict
			ip_dict[object] = subnet.group("this")
			#print "3" + object + subnet.group("this")
		#line declares a service
		elif re.match(r"\s?service (tcp |udp )", line):
			service_group = re.search(r"(.* )(?P<this>[^\s]+)$", line)
			service = service_group.group("this")
			
			ip_dict[object] = service
			#print "4" + object + service
		iter_counter += 1
	#for key, value in ip_dict.iteritems():
	#	print key, value
	return 0
	
#extract object-group networks into ip_dict
def extract_object_group_networks():
	#print "in extract_object_group_networks"
	
	#list and variable to hold object and lines that belong to that object
	lines = []
	object_group = ""
	
	#go through the file_dict one line at a time
	iter_counter = 0
	while iter_counter < len(file_dict):
	
	#go through output file one line at a time
		line = file_dict[iter_counter]
		
		#take out newline at the end
		line = re.sub(r"\s$","",line)
		
		#if the line declares a range, swap out the space for a dash
		if re.match(r".*range \d+ \d+$", line):
			line = re.sub(r"(?P<one>range \d+) (?P<two>[^\s]+)$", r"\g<one>-\g<two>", line)
			
		#if the line declares a new object-group
		if re.match(r'^object-group.*', line):
			#if it's not the first time an object-group is declared, add hosts from previous lines to the dict, then reset
			if object_group != "":
				ip_dict[object_group] = lines
			lines = []
			object = re.search(r"(object-group )([^\s]+ )(?P<this>[^\s]+)", line)
			object_group = object.group("this")
		
		#if the line declares a network-object in the object-group
		elif re.match(r'^\s?network-object.*', line):
			host_group = re.search(r"(\s?network-object (object |host )?)(?P<this>.*)",line)
			host = host_group.group("this")
			lines.append(host)
		
		#if the line declares a group-object in the object-group
		elif re.match(r"^\s?group-object.*", line):
			host_group = re.search(r"(\s?group-object )(?P<this>[^\s]+)$",line)
			host = host_group.group("this")
			lines.append(host)
		
		#if the line declares a port-object in the object-group
		elif re.match(r"^\s?port-object.*", line):
			host_group = re.search(r"(\s?port-object.* )(?P<this>[^\s]+)$",line)
			host = host_group.group("this")
			lines.append(host)
		
		#if the line declares a service-object
		elif re.match(r"\s?service-object.*",line):
			host_group = re.search(r"(\s?service-object.* )(?P<this>[^\s]+)$",line)
			host = host_group.group("this")
			lines.append(host)
		
		#if the line declares a protocol-object
		elif re.match(r"^\s?protocol-object.*", line):
			host_group = re.search(r"(\s?protocol-object.* )(?P<this>[^\s]+)$",line)
			host = host_group.group("this")
			lines.append(host)
		
		#if the line declares an icmp-object
		elif re.match(r"\s?icmp-object.*", line):
			host_group = re.search(r"(\s?icmp-object.* )(?P<this>[^\s]+)$",line)
			host = host_group.group("this")
			lines.append(host)			
		
		iter_counter += 1
		
	return 0
	
#return IP for object
def dict_lookup(str):
	#print "in dict_lookup"
	return ip_dict[str]

#replace named objects with IP addresses
def name_to_ip(dict):
	#print "in name_to_ip"
	for key, value in dict.iteritems():
		#the value can be a single IP address, or a list.
		if isinstance(value, list):
			for i in value:
				#store the index value of the current list item, and duplicate as counter
				position = value.index(i)
				counter = position
				
				#if the current list item also appears in ip_dict as a key, meaning it must be a named object
				if i in ip_dict:
					#The value for the named object (i) could be another list
					if isinstance(dict_lookup(i), list):
						#duplicate the list and iterate through the items. for each list item, store it as a value for the current named object. Then remove the original value, as the named object has now been replaced with an IP address
						new_i = dict_lookup(i)
						for j in new_i:
							value.insert(counter, j)
							counter += 1
						value.remove(i)
					
					#if the value for the named object is not a list but an IP address, then just replace the named object with the IP address
					else:
						value[position] = dict_lookup(i)
				
				#if the current list item does not appear in ip_dict as a key, then it should itself be an IP address and nothing needs to be done. 
				else:
					pass
		
		#if the value is not a list then it could be an IP address or port and nothing else needs to be done
		elif re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\d)", value):
			pass
		
		else:
			name_to_ip = dict_lookup(value)
			
			if isinstance(name_to_ip, list):
				for i in name_to_ip:
					#store the index value of the current list item, and duplicate as counter
					position = name_to_ip.index(i)
					counter = position
				
					#if the current list item also appears in ip_dict as a key, meaning it must be a named object
					if i in ip_dict:
						#The value for the named object (i) could be another list
						if isinstance(dict_lookup(i), list):
							#duplicate the list and iterate through the items. for each list item, store it as a value for the current named object. Then remove the original value, as the named object has now been replaced with an IP address
							new_i = dict_lookup(i)
							for j in new_i:
								name_to_ip.insert(counter, j)
								counter += 1
							name_to_ip.remove(i)
						
						#if the value for the named object is not a list but an IP address, then just replace the named object with the IP address
						else:
							name_to_ip[position] = dict_lookup(i)
							
					#if the current list item does not appear in ip_dict as a key, then it should itself be an IP address and nothing needs to be done. 
					else:
						#print i
						pass
			else:
				pass
			
			del dict[key]
			dict[key] = name_to_ip
				
			
	#for key, value in dict.iteritems():
	#	print key, value
	return dict

#populate the nat_dict with info from the configuration file
def pop_nat_dict():
	#print "in parse_nat"
	#go through the file_dict one line at a time
	iter_counter = 0
	trigger = 0
	nat_inside = ""
	nat_outside = ""
	while iter_counter < len(file_dict):
	#with open(sys.argv[2], "r") as nat_file:
		line = file_dict[iter_counter]
		#for line in nat_file:
		line = re.sub(r"\s$","",line)
				
		if re.match(r"\s?nat \([^\s]+,[^\s]+\)( after-auto)? source.*", line):
			inside_group = re.search(r".*(dynamic |static )(?P<this>[^\s]+)", line)
			outside_group = re.search(r".*(dynamic | static )([^\s]+\s)(?P<this>[^\s]+)", line)
			#print "!!!!!!!!!!!!!!!!!!!!!!!!!!"
			inside = inside_group.group("this")
			outside = outside_group.group("this")
			#print inside + " -- " + outside
			
			nat_dict[outside] = inside
		
		elif re.match(r"\s?object network.*", line):
			#print line
			trigger = 0
			nat_object_group = re.search(r"(.*) (?P<this>[^\s]+)$", line)
			nat_object = nat_object_group.group("this")
			
			if nat_object in ip_dict:
				trigger = 1
				#print "!!!!!!"
				#print nat_object
				nat_inside = nat_object
						
		elif re.match(r"^\s?nat .*", line) and trigger == 1:
			#print "!!!!!!!"
			nat_outside_group = re.search(r"(.*) (?P<this>[^\s]+)$", line)
			nat_outside = nat_outside_group.group("this")
			
			nat_dict[nat_outside] = nat_inside
			#print nat_outside + "!!!!!!"
		#if nat_inside != "" and nat_outside != "":
			#print nat_outside + " -- " + nat_inside
		
		iter_counter += 1
	#for key, value in nat_dict.iteritems():
	#	print key, value
		
	return 0

#replace 
	
#print out the file_dict
def print_file_dict():
	iter_counter = 0
	while iter_counter < len(file_dict):
		print file_dict[iter_counter]
		iter_counter += 1
	
	return 0

#print out the nat_dict
def print_dict(dict):
	for key, value in dict.iteritems():
		print key, value
		
	return 0

def main():
	#argument parsing, later to be put into a function
	parser = argparse.ArgumentParser()
	parser.add_argument("config_file", help="Cisco Firewall Configuration File")
	parser.add_argument("-i", "--ip", help="convert all named objects to IP addresses", action="store_true")
	parser.add_argument("-o", "--object", help="parses out named objects", action = "store_true")
	parser.add_argument("-n", "--nat", help="parses out NAT tables", action = "store_true")
	args = parser.parse_args()
	
	if not args.object and not args.nat:
		print "You have to specify at least -o or -n\n"
		exit(1)
	
	prepop_dict()	
	file_to_dict(args.config_file)
	extract_network_objects()
	extract_object_group_networks()
	
	if args.object and not args.nat:
		my_dict = ip_dict
	elif args.nat and not args.object:
		pop_nat_dict()
		my_nat_dict = nat_dict
	else:
		pop_nat_dict()
		my_dict = ip_dict
		my_nat_dict = nat_dict
		
	if args.ip:
		if args.nat:
			my_dict = name_to_ip(ip_dict)
			my_nat_dict = name_to_ip(nat_dict)
		else:
			my_dict = name_to_ip(my_dict)
	
	if args.object and not args.nat:
		print_dict(my_dict)
	elif args.nat and not args.object:
		print_dict(my_nat_dict)
	else:
		print_dict(my_dict)
		print_dict(my_nat_dict)
	
	return 0

main()