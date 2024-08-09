#!/usr/bin/env python3
import nmap
import re

# Regular Expression Pattern to recognise IPv4 addresses.
ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
# Regular Expression Pattern to extract the number of ports you want to scan.
# You have to specify (ex 10-100)
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
# Initialising the port numbers, will be using the variables later on.
port_min = 0
port_max = 65535

# Basic user interface header
print(r""" 

    /$$   /$$             /$$                                      
   | $$$ | $$            | $$                                      
   | $$$$| $$  /$$$$$$  /$$$$$$   /$$$$$$/$$$$   /$$$$$$   /$$$$$$ 
   | $$ $$ $$ /$$__  $$|_  $$_/  | $$_  $$_  $$ |____  $$ /$$__  $$
   | $$  $$$$| $$$$$$$$  | $$    | $$ \ $$ \ $$  /$$$$$$$| $$  \ $$
   | $$\  $$$| $$_____/  | $$ /$$| $$ | $$ | $$ /$$__  $$| $$  | $$
   | $$ \  $$|  $$$$$$$  |  $$$$/| $$ | $$ | $$|  $$$$$$$| $$$$$$$/
   |__/  \__/ \_______/   \___/  |__/ |__/ |__/ \_______/| $$____/ 
                                                         | $$      
                                                         | $$      
                                                         |__/         """)
print("\n****************************************************************")
print("\n* Copyright of kunal ramraje, 2024                              *")
print("\n*                                                               *")
print("\n****************************************************************")

def scan_host(ip, ports):
    nm = nmap.PortScanner()
    nm.scan(ip, ports)
    host_infos = []

    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            if nm[ip][proto][port]['state'] == 'open':
                host_info = {
                    'ip': ip,
                    'os': nm[ip].get('osclass', {}).get('osfamily', 'Unknown'),
                    'port': port,
                    'name': nm[ip][proto][port]['name'],
                    'product': nm[ip][proto][port]['product'],
                    'version': nm[ip][proto][port]['version'],
                }
                host_infos.append(host_info)

    return host_infos

# Ask user to input the ip address they want to scan.
while True:
    ip_add_entered = input("\nEnter the ip address to scan: ")
    if ip_add_pattern.search(ip_add_entered):
        print(f"{ip_add_entered} is a valid ip address")
        break

while True:
    print("Enter the range of ports to scan in format (ex would be 60-120)")
    port_range = input("Enter port range: ")
    port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        break

host_infos = scan_host(ip_add_entered, f"{port_min}-{port_max}")
for host_info in host_infos:
    print(f"IP: {host_info['ip']}, "
          f"OS: {host_info['os']}, "
          f"Port: {host_info['port']}, "
          f"Name: {host_info['name']}, "
          f"Product: {host_info['product']}, "
          f"Version: {host_info['version']}")
