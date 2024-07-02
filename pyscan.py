import socket
import sys
from ipaddress import IPv4Network, ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if len(sys.argv) <= 2 :
    print("[!] No parameter found. Aborting.")
    print("[!] Please provide an IP range or file and ports to scan.")
    print("[EXAMPLE] > python3 pyscan.py 192.168.0.0/24 80,443")
    print("[EXAMPLE] > python3 pyscan.py 192.168.0.123 445")
    print("[EXAMPLE] > python3 pyscan.py IPS.txt 135,139,3389")
    sys.exit()
arg = sys.argv[-2]
print("*** Scanning range " + arg + " ***")

arg2 = sys.argv[-1]
ports = arg2.split(",")

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


for key in RESULTS_IP.keys():
    if len(RESULTS_IP[key]) == 0:
        print(f"All ports {key} are closed/filtered\n\n")
    else:
        print(f"\n[+] MACHINES WITH PORT {key} OPEN")
        with open(f"PyScan_port_{key}.txt", "w") as file:
            for ip in RESULTS_IP[key]:
                print(ip)
                file.write(ip+"\n")
        file.close()
