import socket
import sys
from ipaddress import IPv4Network, ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if len(sys.argv) <= 1 :
    print("[!] No parameter found. Aborting.")
    print("[!] Please provide an IP range or file.")
    print("[EXAMPLE] > python3 findSMB.py 192.168.0.0/24")
    print("[EXAMPLE] > python3 findSMB.py 192.168.0.123")
    print("[EXAMPLE] > python3 findSMB.py IPS.txt")
    sys.exit()
arg = sys.argv[-1]
print("*** Scanning range " + arg + " ***")
ports = [445]

########################################################################
MAX_WORKERS = 20    # MAX CONCURRENT REQUESTS
VERBOSE = False     # False : TO DISPLAY ONLY OPEN PORTS
########################################################################

SMB_IP = []

def scan_ip(ip_address):
    if VERBOSE :
        print(f"-> Scanning {ip_address}")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            print(f"[+] SMB FOUND on {ip_address}:{port}")
            SMB_IP.append(ip_address)
        else:
            pass
        sock.close()

def log_result(IP):
    file=open("PSCAN_open_SMB.txt","a+")
    file.write(IP+"\n")
    file.close()

try:
    ip_address = ip_address(arg)
    scan_ip(str(ip_address))
except ValueError:
    try:
        network = IPv4Network(arg)
        ip_addresses = [str(ip) for ip in network]
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            results = executor.map(scan_ip, ip_addresses)
            for result in results:
                pass
    except ValueError:
        try:
            with open(arg) as f:
                ip_addresses = [line.strip() for line in f]
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    results = executor.map(scan_ip, ip_addresses)
                    for f in as_completed(results):
                        pass
        except FileNotFoundError:
            print(f"{arg} is not a valid IP address, network in CIDR notation, or file")
            print("Aborting...")
            sys.exit()

print("\n")
print("--------------------------------")
print("----------- RESULT -------------")
print("--------------------------------")


if len(SMB_IP) == 0 :
    print("No SMB found")
else :
    for ip in SMB_IP :
        print(ip)
        log_result(ip)
