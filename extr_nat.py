import io
import re
import sys
import netaddr

#globally accessible dict to hold network objects
my_dict = {}

#verify user entered enough cmd line arguments
def check_args():
	if len(sys.argv) < 3:
		print "Usage: python extr_nat.py input_file output_file"
		exit(1)
	
#prepopulate my_dict with known port aliases
def prepop_dict():
	my_dict["https"] = "443"
	my_dict["smtp"] = "25"
	my_dict["www"] = "80"
	
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
			
			#convert netmask to cidr in lines that contain the string "subnet" or "ip address", or if the line is "object-network <IP> <Subnet>"
			#if (re.match(r".*?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*?", line) and (line.find("subnet") != -1 or line.find("ip address") != -1)) or re.match(r"\s?network-object\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s?", line):
			#	match_netmask = re.match(r".*?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
			#	netmask = match_netmask.group(1)
			#	line = re.sub(r"(?<=\d)\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", mask_to_cidr2, line)
			
			new_file.write(line)
	new_file.close()
	return 0

#primitive netmask to CIDR conversion. takes result from re.match as argument
def mask_to_cidr2(netmask):
	#obtain the part of netmask we're interested in 
	mask = netmask.group(0)
	
	#remove unwanted whitespace at the beginning of the line
	mask = re.sub("^\s", "", mask)
	
	#if the string is not in the format of a netmask
	if not re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", mask):
		print mask + " is not a netmask"
		exit(1)
	
	#if string is a netmask
	else:
		
		#find the four octets and convert them to binary
		octets = re.findall(r"\d{1,3}", mask)
		binary = format(int(octets[0]), "b") + format(int(octets[1]), "b") + format(int(octets[2]), "b") + format(int(octets[3]), "b")
	
	#return the number of 1's that appear in the binary form of the octets
	return "/" + str(binary.count("1"))

#Extract network objects
def extract_network_objects():
	#prevLine = ""
	object = ""
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
			
			elif re.match(r"subnet\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line):
				#print "i found a subnet"
				subnet = re.search(r"(?<=subnet\s).*", line)
				
				#add network object and ip to dict
				my_dict[object.group(0)] = subnet.group(0)
				
			#store the line in the previous line variable for later use
			#prevLine = re.sub("\s\n","", line)
	
	return 0
	
#extract object-group networks
def extract_object_group_networks():
	lines = []
	object_group = ""
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
				#print object.group(2)
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
			
			#if the line is something else
			else:
				continue
	
	return 0
	
#return IP for object
def dict_lookup(str):
	#print str
	return my_dict[str]

#replace named objects with IP addresses
def name_to_ip():
	for key, value in my_dict.iteritems():
		#print "next"
		#print key, value
		
		#if the value is a list
		if isinstance(value, list):
			#print "dealing with a list"
						
			#iterate through the values
			for i in value:
				#print i
				position = value.index(i)
				counter = position
				if i in my_dict:
					#if the value is another object that is a list
					if isinstance(dict_lookup(i), list):
						print "!!!!!!!!!!!!!!!"
						new_i = dict_lookup(i)
						for j in new_i:
							value.insert(counter, j)
							counter += 1
						value.remove(i)
					
					else:
						#print "this was in the dict"
						value[position] = dict_lookup(i)
				
				#for each value, check to see if it's a valid IP address
				#if netaddr.valid_ipv4(i) == True:
				#	print "this is a valid IP"
								
				#if the value is a range
				#if re.match(r"\d-\d", i):
				#	print "this is a range"
				
				#else:
				#	print "pass"
				#	pass
				#else:
					#while isinstance()
					#print "this is not a valid IP and should be: " + str(my_dict[i])
		#else:
		#	print "the above is not a list"
			
		print key, value
		
	return 0

def main():
	check_args()
	prepop_dict()	
	remove_lines()
	extract_network_objects()
	extract_object_group_networks()
	name_to_ip()
	
	return 0

main()
print "DONE"