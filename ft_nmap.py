
import nmap
import sys

def	is_valid_ip(ip_addr):
	ip_addr_splited = ip_addr.split('.')
	if len(ip_addr_splited) != 4:
		print('Invalid IP Address Because lot of segment in IP..!')
		return False
	for i in ip_addr_splited:
		try:
			int(i)
		except (ValueError, TypeError):
			print('Invalid IP Address Because a Part of IP in not int')
			return False
		if int(i) > 255 or int(i) < 0:
			print('Invalid IP Address Because the number are out IP range..!')
			return False
	return True
scanner = nmap.PortScanner()
print("Welcome, this is a nmap automation tool by kirwa")
print("<---------------------------------------------->")
if len(sys.argv) == 1:
	ip_addr = input("Please enter the IP address you want to scan: ")
else:
	ip_addr = sys.argv[1]
while is_valid_ip(ip_addr) == False:
	ip_addr = input("Please enter a valid IP address you want to scan: ")
print("IP Address is Good..!")
resp = 0
while resp not in ['1','2','3'] :
	resp = input("""Please enter the type of scan you want to run
	1) SYN ACK Scan
	2) UPD Scan
	3) Comprehensive Scan\n""")
print("You Have Selected The Option: {}".format(resp))
if resp == '1':
	print("Nmap Version: {}".format(scanner.nmap_version()))
	scanner.scan(ip_addr, '1-1024', '-v -sS')
	print(scanner.scaninfo())
	print("IP Status: {}".format(scanner[ip_addr].state()))
	print(scanner[ip_addr].all_protocols())
	print("Open Ports; {}".format(scanner[ip_addr]['tcp'].keys()))
elif resp == '2':
	print("Nmap Version: {}".format(scanner.nmap_version()))
	scanner.scan(ip_addr, '1-1024', '-v -sU')
	print(scanner.scaninfo())
	print("IP Status: {}".format(scanner[ip_addr].state()))
	print(scanner[ip_addr].all_protocols())
	print("Open Ports; {}".format(scanner[ip_addr]['udp'].keys()))
elif resp == '3':
	print("Nmap Version: {}".format(scanner.nmap_version()))
	scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
	print(scanner.scaninfo())
	print("IP Status: {}".format(scanner[ip_addr].state()))
	print(scanner[ip_addr].all_protocols())
	print("Open Ports; {}".format(scanner[ip_addr]['tcp'].keys()))
else:
	print("Invalid choose...!")
