
import nmap

scanner = nmap.PortScanner()
print("Welcome, this is a nmap automation tool by kirwa")
print("<---------------------------------------------->")
ip_addr = input("Please enter the IP address you want to scan: ")

#sure = input("Are you that you want to Scan this Address: {} [yes/no]".format(ip_addr))

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
