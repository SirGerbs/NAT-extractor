import io
import re
import sys
import netaddr

#globally accessible dict to hold network objects
my_dict = {}
nat_dict = {}

#verify user entered enough cmd line arguments
def check_args():
	if len(sys.argv) < 3:
		print "Usage: python extr_nat.py input_file output_file"
		exit(1)
	
	return 0
	
#prepopulate my_dict with known port aliases
def prepop_dict():
	my_dict["ah"] = "51"
	my_dict["eigrp"] = "88"
	my_dict["esp"] = "50"
	my_dict["gre"] = "47"
	my_dict["icmp"] = "1"
	my_dict["icmp6"] = "58"
	my_dict["igmp"] = "2"
	my_dict["igrp"] = "9"
	my_dict["ip"] = "0"
	my_dict["ipinip"] = "4"
	my_dict["ipsec"] = "50"
	my_dict["nos"] = "90"
	my_dict["ospf"] = "89"
	my_dict["pcp"] = "108"
	my_dict["pim"] = "103"
	my_dict["pptp"] = "47"
	my_dict["snp"] = "109"
	my_dict["tcp"] = "6"
	my_dict["udp"] = "17"
	my_dict["aol"] = "5190"
	my_dict["bgp"] = "179"
	my_dict["biff"] = "512"
	my_dict["bootpc"] = "68"
	my_dict["bootps"] = "67"
	my_dict["chargen"] = "19"
	my_dict["citrix-ica"] = "1494"
	my_dict["cmd"] = "514"
	my_dict["etiqbe"] = "2748"
	my_dict["daytime"] = "13"
	my_dict["discard"] = "9"
	my_dict["domain"] = "53"
	my_dict["dnsix"] = "195"
	my_dict["echo"] = "7"
	my_dict["exec"] = "512"
	my_dict["finger"] = "79"
	my_dict["ftp"] = "21"
	my_dict["ftp-data"] = "20"
	my_dict["gopher"] = "70"
	my_dict["https"] = "443"
	my_dict["h323"] = "1720"
	my_dict["hostname"] = "101"
	my_dict["ident"] = "113"
	my_dict["imap4"] = "143"
	my_dict["irc"] = "194"
	my_dict["isakmp"] = "500"
	my_dict["kerberos"] = "750"
	my_dict["klogin"] = "543"
	my_dict["kshell"] = "544"
	my_dict["ldap"] = "389"
	my_dict["ldaps"] = "636"
	my_dict["lpd"] = "515"
	my_dict["login"] = "513"
	my_dict["lotusnotes"] = "1352"
	my_dict["mobile-ip"] = "434"
	my_dict["nameserver"] = "42"
	my_dict["netbios-ns"] = "137"
	my_dict["netbios-dgm"] = "138"
	my_dict["netbios-ssn"] = "139"
	my_dict["nntp"] = "119"
	my_dict["ntp"] = "123"
	my_dict["pcanywhere-status"] = "5632"
	my_dict["pcanywhere-data"] = "5631"
	my_dict["pim-auto-rp"] = "496"
	my_dict["pop2"] = "109"
	my_dict["pop3"] = "110"
	my_dict["pptp"] = "1723"
	my_dict["radius"] = "1645"
	my_dict["radius-acct"] = "1646"
	my_dict["rip"] = "520"
	my_dict["secureid-udp"] = "5510"
	my_dict["smtp"] = "25"
	my_dict["snmp"] = "161"
	my_dict["snmptrap"] = "162"
	my_dict["sqlnet"] = "1521"
	my_dict["ssh"] = "22"
	my_dict["sunrpc"] = "111"
	my_dict["syslog"] = "514"
	my_dict["rpc"] = "111"
	my_dict["tacacs"] = "49"
	my_dict["talk"] = "517"
	my_dict["telnet"] = "23"
	my_dict["tftp"] = "69"
	my_dict["time"] = "37"
	my_dict["uucp"] = "540"
	my_dict["who"] = "513"
	my_dict["whois"] = "43"
	my_dict["www"] = "80"
	my_dict["xmdcp"] = "177"
	my_dict["nfs"] = "2049"
	my_dict["sip"] = "5060"
	my_dict["rtsp"] = "554"
	
	return 0
	
#function meant to format config file into more usable format
def remove_lines():
	#new file to store result of removing lines
	new_file = open(sys.argv[2], "w")
	with open(sys.argv[1], "r") as file:
		for line in file:
			#if the line is empty, ignore it
			if re.match(r'^\s*$', line):
				#new_file.write("the line used to be " + line + " but I removed an empty line\n")
				continue
				
			#if the line has "<--- More --->", remove it
			if re.match(r'.*?<--- More --->.*?', line):
				line = re.sub("<--- More --->\s*","",line)
				#new_file.write(line)
				#continue
				
			#if the line contains a description, ignore it
			if re.match(r"^\s?description",line):
				#new_file.write("the line used to be " + line + " but I removed description\n")
				continue
			
			#if the line begins with whitespace
			if re.match(r"^\s.*", line):
				line = re.sub(r"^\s", "", line)
			
			#format address range notations
			if line.find("range") != -1:
				line = re.sub(r"(.*?range\s.*?)(\s)","\g<1>-", line)
			
			new_file.write(line)
	new_file.close()
	return 0

#primitive netmask to CIDR conversion. takes result from re.match as argument
def mask_to_cidr2(netmask):
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

#Extract network objects
def extract_network_objects():
	#object variable to store named objects
	object = ""
	
	#go through the output file one line at a time
	with open(sys.argv[2], "r") as file:
		for line in file:
			#take out newline at the end
			line = re.sub(r"\s*$","",line)
			
			#if the line declares a new object
			if line.find("object") != -1:
				object = re.search(r'(?<=object network\s).*', line)
				
			#regex matches "host <IP>"
			if re.match(r'\s?host \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line):
				#extract IP address belonging to object				
				ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
				
				#add network object and ip to dict
				my_dict[object.group(0)] = ip.group(0)
			
			#regex matches "range <IP>-<IP>"
			elif re.match(r'\s?range \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line):
				range = re.search(r"(?<=range\s).*", line)
				
				#add network object and ip to dict
				my_dict[object.group(0)] = range.group(0)
			
			#line declares a subnet
			elif re.match(r"subnet\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line):
				#print "i found a subnet"
				subnet = re.search(r"(?<=subnet\s).*", line)
				
				#add network object and ip to dict
				my_dict[object.group(0)] = subnet.group(0)
	
	return 0
	
#extract object-group networks
def extract_object_group_networks():
	#list and variable to hold objects and lines that belong to that object
	lines = []
	object_group = ""
	
	#go through output file one line at a time
	with open(sys.argv[2], "r") as file:
		for line in file:
			#take out newline at the end
			line = re.sub(r"\n","",line)
			
			#if the line declares a new object-group
			if re.match(r'^object-group.*', line):
				#if it's not the first time an object-group is declared, add hosts from previous lines to the dict, then reset
				#print line
				if object_group != "":
					my_dict[object_group] = lines
				lines = []
				object = re.search(r"(object-group [^\s]* )([^\s]*)", line)
				object_group = object.group(2)
			
			#if the line declares a network-object in the object-group
			elif re.match(r'^network-object.*', line):
				lines.append(re.sub(r"\s?network-object\s((object|host)\s)?", "", line))
			
			#if the line declares a group-object in the object-group
			elif re.match(r"^group-object.*", line):
				lines.append(re.sub("^group-object\s", "", line))
			
			#if the line declares a port-object in the object-group
			elif re.match(r"^port-object.*", line):
				lines.append(re.sub(r"^port-object\s\w+\s", "", line))
			
			#if the line is something else, ignore it
			else:
				continue
	
	return 0
	
#return IP for object
def dict_lookup(str):
	
	return my_dict[str]

#replace named objects with IP addresses
def name_to_ip():
	for key, value in my_dict.iteritems():
		#the value can be a single IP address, or a list.
		if isinstance(value, list):
			for i in value:
				#store the index value of the current list item, and duplicate as counter
				position = value.index(i)
				counter = position
				
				#if the current list item also appears in my_dict as a key, meaning it must be a named object
				if i in my_dict:
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
				
				#if the current list item does not appear in my_dict as a key, then it should itself be an IP address and nothing needs to be done. 
				else:
					pass
		
		#if they value is not a list then it should be an IP address and nothing else needs to be done
		else:
			pass
				
	return 0

#time to do stuff with NAT tables line 8789
def parse_nat():
	with open(sys.argv[2], "r") as nat_file:
		nat_inside = ""
		nat_outside = ""
		trigger = 0
		for line in nat_file:
			re.sub(r"\n","",line)
					
			if re.match(r"nat \([^\s]+,[^\s]+\)( after-auto)? source.*", line):
				inside_group = re.search(r".*(dynamic |static )(?P<this>[^\s]+)", line)
				outside_group = re.search(r".*(dynamic | static )([^\s]+\s)(?P<this>[^\s]+)", line)
				#print "!!!!!!!!!!!!!!!!!!!!!!!!!!"
				inside = inside_group.group("this")
				outside = outside_group.group("this")
				#print inside + " -- " + outside
				
				nat_dict[outside] = inside
			
			elif re.match(r"object network.*", line):
				trigger = 0
				nat_object_group = re.search(r"(.*) (?P<this>.*)$", line)
				nat_object = nat_object_group.group("this")
				
				if nat_object in my_dict:
					trigger = 1
					#print "!!!!!!"
					#print nat_object
					nat_inside = nat_object
					continue
			
			elif re.match(r"^nat .*", line) and trigger == 1:
				nat_outside_group = re.search(r"(.*) (?P<this>[^\s]+)$", line)
				nat_outside = nat_outside_group.group("this")
				
				nat_dict[nat_outside] = nat_inside
				#print nat_outside + "!!!!!!"
			#if nat_inside != "" and nat_outside != "":
				#print nat_outside + " -- " + nat_inside
	
	for key, value in nat_dict.iteritems():
		print key, value
		
	return 0
	
def main():
	check_args()
	prepop_dict()	
	remove_lines()
	extract_network_objects()
	extract_object_group_networks()
	name_to_ip()
	parse_nat()
	
	#print my_dict["SCAN-VRF01-PAT"]
	
	return 0

main()