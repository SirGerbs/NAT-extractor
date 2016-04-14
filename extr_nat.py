import io
import re
import sys
import argparse

#class to hold global variables and such
class mem:
	ip = False
	object = False
	nat = False
	cidr = False
	file_dict = {}
	ip_dict = {}
	nat_dict = {}
	port_dict = {}

#prepopulate mem.port_dict with known port aliases
def prepop_dict():
	mem.port_dict["ah"] = "51"
	mem.port_dict["eigrp"] = "88"
	mem.port_dict["esp"] = "50"
	mem.port_dict["gre"] = "47"
	mem.port_dict["icmp"] = "1"
	mem.port_dict["icmp6"] = "58"
	mem.port_dict["igmp"] = "2"
	mem.port_dict["igrp"] = "9"
	mem.port_dict["ip"] = "0"
	mem.port_dict["ipinip"] = "4"
	mem.port_dict["ipsec"] = "50"
	mem.port_dict["nos"] = "90"
	mem.port_dict["ospf"] = "89"
	mem.port_dict["pcp"] = "108"
	mem.port_dict["pim"] = "103"
	mem.port_dict["pptp"] = "47"
	mem.port_dict["snp"] = "109"
	mem.port_dict["tcp"] = "6"
	mem.port_dict["udp"] = "17"
	mem.port_dict["aol"] = "5190"
	mem.port_dict["bgp"] = "179"
	mem.port_dict["biff"] = "512"
	mem.port_dict["bootpc"] = "68"
	mem.port_dict["bootps"] = "67"
	mem.port_dict["chargen"] = "19"
	mem.port_dict["citrix-ica"] = "1494"
	mem.port_dict["cmd"] = "514"
	mem.port_dict["etiqbe"] = "2748"
	mem.port_dict["daytime"] = "13"
	mem.port_dict["discard"] = "9"
	mem.port_dict["domain"] = "53"
	mem.port_dict["dnsix"] = "195"
	mem.port_dict["echo"] = "7"
	mem.port_dict["exec"] = "512"
	mem.port_dict["finger"] = "79"
	mem.port_dict["ftp"] = "21"
	mem.port_dict["ftp-data"] = "20"
	mem.port_dict["gopher"] = "70"
	mem.port_dict["https"] = "443"
	mem.port_dict["h323"] = "1720"
	mem.port_dict["hostname"] = "101"
	mem.port_dict["ident"] = "113"
	mem.port_dict["imap4"] = "143"
	mem.port_dict["irc"] = "194"
	mem.port_dict["isakmp"] = "500"
	mem.port_dict["kerberos"] = "750"
	mem.port_dict["klogin"] = "543"
	mem.port_dict["kshell"] = "544"
	mem.port_dict["ldap"] = "389"
	mem.port_dict["ldaps"] = "636"
	mem.port_dict["lpd"] = "515"
	mem.port_dict["login"] = "513"
	mem.port_dict["lotusnotes"] = "1352"
	mem.port_dict["mobile-ip"] = "434"
	mem.port_dict["nameserver"] = "42"
	mem.port_dict["netbios-ns"] = "137"
	mem.port_dict["netbios-dgm"] = "138"
	mem.port_dict["netbios-ssn"] = "139"
	mem.port_dict["nntp"] = "119"
	mem.port_dict["ntp"] = "123"
	mem.port_dict["pcanywhere-status"] = "5632"
	mem.port_dict["pcanywhere-data"] = "5631"
	mem.port_dict["pim-auto-rp"] = "496"
	mem.port_dict["pop2"] = "109"
	mem.port_dict["pop3"] = "110"
	mem.port_dict["pptp"] = "1723"
	mem.port_dict["radius"] = "1645"
	mem.port_dict["radius-acct"] = "1646"
	mem.port_dict["rip"] = "520"
	mem.port_dict["secureid-udp"] = "5510"
	mem.port_dict["smtp"] = "25"
	mem.port_dict["snmp"] = "161"
	mem.port_dict["snmptrap"] = "162"
	mem.port_dict["sqlnet"] = "1521"
	mem.port_dict["ssh"] = "22"
	mem.port_dict["sunrpc"] = "111"
	mem.port_dict["syslog"] = "514"
	mem.port_dict["rpc"] = "111"
	mem.port_dict["tacacs"] = "49"
	mem.port_dict["talk"] = "517"
	mem.port_dict["telnet"] = "23"
	mem.port_dict["tftp"] = "69"
	mem.port_dict["time"] = "37"
	mem.port_dict["uucp"] = "540"
	mem.port_dict["who"] = "513"
	mem.port_dict["whois"] = "43"
	mem.port_dict["www"] = "80"
	mem.port_dict["xmdcp"] = "177"
	mem.port_dict["nfs"] = "2049"
	mem.port_dict["sip"] = "5060"
	mem.port_dict["rtsp"] = "554"
	
	return 0
	
#Modify input config file to remove unwanted lines, and then store in file_dict for later usage
def file_to_dict(config_file):
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
			
			mem.file_dict[line_counter] = line
			line_counter += 1
	iter_counter = 0
	
	return 0

#primitive netmask to CIDR conversion.
def mask_to_cidr(netmask):
	netmask = re.search("^(?P<ip>(\d{1,3}\.){3}\d{1,3}) (?P<mask>(\d{1,3}\.){3}\d{1,3})$", netmask)
	ip = netmask.group("ip")
	mask = netmask.group("mask")
	
	#if string is a netmask find the four octets and convert them to binary
	octets = re.findall(r"\d{1,3}", mask)
	binary = format(int(octets[0]), "b") + format(int(octets[1]), "b") + format(int(octets[2]), "b") + format(int(octets[3]), "b")
	
	#return the number of 1's that appear in the binary form of the octets
	return ip + "/" + str(binary.count("1"))

#Extract network objects into mem.ip_dict
def extract_network_objects():
	#object variable to store named objects
	object = ""
	
	#go through the mem.file_dict one line at a time
	iter_counter = 0
	while iter_counter < len(mem.file_dict):
		line = mem.file_dict[iter_counter]
		
		#take out newline at the end
		line = re.sub(r"\s$","",line)

		#if the line declares a range, swap out the space for a dash
		if re.match(r".*range \d+ \d+$", line):
			line = re.sub(r"(?P<one>range \d+) (?P<two>[^\s]+)$", r"\g<one>-\g<two>", line)
		
		#if the line declares a new object, store the object name in variable so it can be used later; during subsequent line iterations
		if re.match("\s?object (network |service ).*", line):
			object_group = re.search(r"(^\s?object (network |service ))(?P<this>[^\s]+)$", line)
			object = object_group.group("this")
			
		#regex matches "host <IP>"
		elif re.match(r'\s?host (\d{1,3}\.){3}\d{1,3}', line):
			#extract IP address belonging to object				
			ip = re.search(r'(\s?host )(?P<this>[^\s]+)$', line)
						
			#add network object and ip to dict
			mem.ip_dict[object] = ip.group("this")
		
		#regex matches "range <IP>-<IP>"
		elif re.match(r'\s?range (\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}', line):
			range = re.search(r".*range (?P<this>[^\s]+)$", line)
			
			#add network object and ip to dict
			mem.ip_dict[object] = range.group("this")
			
		#line declares a subnet
		elif re.match(r"\s?subnet\s(\d{1,3}\.){3}\d{1,3}\s(\d{1,3}\.){3}\d{1,3}", line):
			subnet = re.search(r"(\s?subnet )(?P<this>(\d{1,3}\.){3}\d{1,3}\s(\d{1,3}\.){3}\d{1,3})$", line)
			
			#add network object and ip to dict
			mem.ip_dict[object] = subnet.group("this")
			
		#line declares a service
		elif re.match(r"\s?service (tcp |udp )", line):
			service = re.search(r"(.* )(?P<this>[^\s]+)$", line)
			
			#add network object and ip to dict			
			mem.ip_dict[object] = service.group("this")
			
		iter_counter += 1
		
	return 0
	
#extract object-group networks into mem.ip_dict
def extract_object_group_networks():
	#list and variable to hold object and lines that belong to that object
	lines = []
	object_group = ""
	
	iter_counter = 0
	while iter_counter < len(mem.file_dict):
	
	#go through the mem.file_dict one line at a time
		line = mem.file_dict[iter_counter]
		
		#take out newline at the end
		line = re.sub(r"\s$","",line)
		
		#if the line declares a range, swap out the space for a dash
		if re.match(r".*range \d+ \d+$", line):
			line = re.sub(r"(?P<one>range \d+) (?P<two>[^\s]+)$", r"\g<one>-\g<two>", line)
			
		#if the line declares a new object-group, store it in the object_group variable for later use - during a later line iteration
		if re.match(r'^object-group.*', line):
			#If the line declares a new object, add previous object plus IPs to the dict, then reset. This does not fire if it's the first time an object is declared
			if object_group != "":
				mem.ip_dict[object_group] = lines
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
	
#return IP address or port number for named object
def dict_lookup(str):
	if str in mem.ip_dict:
		return mem.ip_dict[str]
	elif str in mem.port_dict:
		return mem.port_dict[str]
	else:
		return 0

#replace named objects with IP addresses. This function has some recursion because a named object could contain a list of named objects, which in turn could also contain lists of named objects
def name_to_ip(dict):
	for key, value in dict.iteritems():
		#the value can be a single IP address, or a list.
		if isinstance(value, list):
			for i in value:
				#store the index value of the current list item, and duplicate as counter
				position = value.index(i)
				counter = position
				
				#if the current list item also appears in mem.ip_dict as a key it must be a named object
				if i in mem.ip_dict or i in mem.port_dict:
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
				
				#if the current list item does not appear in mem.ip_dict as a key, then it should itself be an IP address and nothing needs to be done. 
				else:
					pass
		
		#if the value is not a list then it could be an IP address or port and nothing else needs to be done
		elif re.match(r"((\d{1,3}\.){3}\d{1,3}|\d+)", value):
			pass
		
		#if the value is not a list, and not an IP address or port, then it must be a named object
		else:
			name_to_ip = dict_lookup(value)
			
			#again, named objects could contain lists so we have to 'unpack' them down to individual IP addresses
			if isinstance(name_to_ip, list):
				for i in name_to_ip:
					#store the index value of the current list item, and duplicate as counter
					position = name_to_ip.index(i)
					counter = position
				
					#if the current list item also appears in mem.ip_dict as a key, meaning it must be a named object
					if i in mem.ip_dict:
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
							
					#if the current list item does not appear in mem.ip_dict as a key, then it should itself be an IP address and nothing needs to be done. 
					else:
						pass
			
			#if the named object does not contain a list of values, do nothing. It seems to me that a named object could contain another named object, so at some point if a named object does not get translated to an IP address, this is where the problem could be
			else:
				pass
			
			#replace the dict entry with the new dict entry. I read it's a bad habit to modify a dict while iterating through it, so this may need to be changed in the future
			del dict[key]
			dict[key] = name_to_ip
				
	return dict

#populate the mem.nat_dict with NAT table info from the configuration file
def pop_nat_dict():
	#declare variables to be used in this function
	iter_counter = 0
	trigger = 0
	nat_inside = ""
	nat_outside = ""
	
	while iter_counter < len(mem.file_dict):
		#go through the mem.file_dict one line at a time
		line = mem.file_dict[iter_counter]
		
		#take out possible whitespace at the end of the line
		line = re.sub(r"\s$","",line)
		
		#this matches "nat (inside,outside) after-auto source dynamic <object> <object>
		if re.match(r"\s?nat \([^\s]+,[^\s]+\)( after-auto)? source.*", line):
			inside_group = re.search(r".*(dynamic |static )(?P<this>[^\s]+)", line)
			outside_group = re.search(r".*(dynamic | static )([^\s]+\s)(?P<this>[^\s]+)", line)
			inside = inside_group.group("this")
			outside = outside_group.group("this")
			
			mem.nat_dict[outside] = inside
		
		#this matches if the line declares an object network. Since this is the same syntax for NAT as it is for the declaration of network objects earlier in the config file, we're using a trigger variable to distinguish between the two
		elif re.match(r"\s?object network.*", line):
			trigger = 0
			nat_object_group = re.search(r"(.*) (?P<this>[^\s]+)$", line)
			nat_object = nat_object_group.group("this")
			
			#the nat object should appear in the mem.ip_dict, as it should have been defined previously. If this is the case, the trigger variable is set to 1
			if nat_object in mem.ip_dict:
				trigger = 1
				nat_inside = nat_object
		
		#If the line declares a NAT translation that should be associated with the network object that came in the line before it
		elif re.match(r"^\s?nat .*", line) and trigger == 1:
			nat_outside_group = re.search(r"(.*) (?P<this>[^\s]+)$", line)
			nat_outside = nat_outside_group.group("this")
			
			mem.nat_dict[nat_outside] = nat_inside
		
		iter_counter += 1
	
	return 0

#this function exists to translate dict keys that are named objects to IP addresses
def key_to_ip():
	new_key_values = {}
	#iterate through mem.nat_dict and check to see if the key is define in mem.ip_dict. If so, place IP in new_key_values dict. This does not fire if the key is a named object that declares a list, as the key for a dict cannot be a list
	for key, value in mem.nat_dict.iteritems():
		if key in mem.ip_dict and not isinstance(dict_lookup(key), list):
			new_key = dict_lookup(key)
			new_key_values[new_key] = value
			
			#change value of original mem.nat_dict key, so it can be found later for deletion
			mem.nat_dict[key] = "-1"
	
	#iterate through the new_key_values dict and use the entries to replace entries in the original mem.nat_dict
	for key, value in new_key_values.iteritems():
		mem.nat_dict[key] = value
	
	#delete all entries from the dict where value == "-1"
	mem.nat_dict = {k:v for k,v in mem.nat_dict.items() if v != '-1'}
	
	return 0

#print out the mem.file_dict. This function is not used in the program and only exists for troubleshooting purposes
def print_file_dict():
	iter_counter = 0
	while iter_counter < len(mem.file_dict):
		print mem.file_dict[iter_counter]
		iter_counter += 1
	
	return 0

#print out a dict
def print_dict(dict):
	for key, value in dict.iteritems():
	
		#if the user specified that they want to receive subnets in CIDR notation, this part of the function executes to replace netmasks with CIDR entries
		if mem.cidr == True:
			if isinstance(value, list): 
				cidr_list = []
				for i in value:
					if re.match(r"(\d{1,3}\.){3}\d (\d{1,3}\.){3}\d", i):
						cidr_list.append(mask_to_cidr(i))
					else:
						cidr_list.append(i)
				print key, str(cidr_list)
			elif re.match(r"(\d{1,3}\.){3}\d (\d{1,3}\.){3}\d", value):
				cidr_value = mask_to_cidr(value)
				print key, cidr_value
			else:
				print key, value	
		
		#if the user did not specify CIDR notation, just print key and value
		else:
			print key, value
	
	return 0

#main program function
def main():
	#argument parsing, later to be put into a function
	parser = argparse.ArgumentParser()
	parser.add_argument("config_file", help="Cisco Firewall Configuration File")
	parser.add_argument("-i", "--ip", help="convert all named objects to IP addresses", action="store_true")
	parser.add_argument("-o", "--object", help="parses out named objects", action = "store_true")
	parser.add_argument("-n", "--nat", help="parses out NAT tables", action = "store_true")
	parser.add_argument("-c", "--cidr", help="display subnets in CIDR notation", action = "store_true")
	args = parser.parse_args()
	
	#if the user did not execute the program correctly
	if not args.object and not args.nat:
		print "You have to specify at least -o or -n\n"
		exit(1)
	
	#set the specified arguments as variables in the mem class
	if args.ip:
		mem.ip = True
	if args.object:
		mem.object = True
	if args.nat:
		mem.nat = True
	if args.cidr:
		mem.cidr = True
	
	#These functions always need to execute for the program to do its job
	prepop_dict()	
	file_to_dict(args.config_file)
	extract_network_objects()
	extract_object_group_networks()
	
	#depending on the cmd line arguments specified, execute specific functions
	if args.object and not args.nat:
		my_dict = mem.ip_dict
	elif args.nat and not args.object:
		pop_nat_dict()
		my_nat_dict = mem.nat_dict
	else:
		pop_nat_dict()
		my_dict = mem.ip_dict
		my_nat_dict = mem.nat_dict
		
	if args.ip:
		if args.nat:
			my_dict = name_to_ip(mem.ip_dict)
			key_to_ip()
			my_nat_dict = name_to_ip(mem.nat_dict)
		else:
			my_dict = name_to_ip(my_dict)
	
	if args.object and not args.nat:
		print_dict(my_dict)
	elif args.nat and not args.object:
		print_dict(my_nat_dict)
	else:
		print_dict(my_dict)
		print_dict(my_nat_dict)

main()
