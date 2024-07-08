import socket
import sys
from ipaddress import IPv4Network, ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if len(sys.argv) <= 2 :
    print("[!] Not enough parameters found. Aborting.")
    print("Usage: python3 pyscan.py target ports [-o]")
    print("  target             	single IP, range or file of IP")
    print("  ports             	list of ports separated by comma") 
    print("  -o             	output the IP with open ports to file")
    sys.exit()
arg = sys.argv[1]
print("*** Scanning range " + arg + " ***")

arg2 = sys.argv[2]
ports = arg2.split(",")
OUTPUT_FILE = '-o' in sys.argv

########################################################################
MAX_WORKERS = 20    # MAX CONCURRENT REQUESTS
VERBOSE = False     # False : TO DISPLAY ONLY OPEN PORTS
########################################################################

RESULTS_IP = {}
for port in ports:
    RESULTS_IP[port] = []

def scan_ip(ip_address):
    if VERBOSE :
        print(f"-> Scanning {ip_address}")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        result = sock.connect_ex((ip_address, int(port)))
        if result == 0:
            print(f"[+] PORT FOUND on {ip_address}:{port}")
            RESULTS_IP[port].append(ip_address)
        else:
            pass
        sock.close()

try:
    ip_address = ip_address(arg)
    scan_ip(str(ip_address))
except ValueError:
    try:
        network = IPv4Network(arg)
        ip_addresses = [str(ip) for ip in network]
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            results = executor.map(scan_ip, ip_addresses)
    except ValueError:
        try:
            with open(arg) as f:
                ip_addresses = [line.strip() for line in f]
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    results = executor.map(scan_ip, ip_addresses)
        except FileNotFoundError:
            print(f"{arg} is not a valid IP address, network in CIDR notation, or file")
            print("Aborting...")
            sys.exit()

print("\n")
print("--------------------------------")
print("----------- RESULT -------------")
print("--------------------------------")


for key in RESULTS_IP.keys():
    if len(RESULTS_IP[key]) == 0:
        print(f"\n[-] All ports {key} are closed/filtered")
    else:
        print(f"\n[+] MACHINES WITH PORT {key} OPEN")
        for ip in RESULTS_IP[key]:
                print(ip)
                if OUTPUT_FILE:
                    with open(f"PyScan_port_{key}.txt", "a") as file:
                        file.write(ip+"\n")
                    file.close()
