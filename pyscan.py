import socket
import sys
from ipaddress import IPv4Network, ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import random

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def help():
    print("Usage: python3 pyscan.py target ports [-o] [-t 10] [-d 0] [-v]")
    print("  target             	single IP, range or file of IP")
    print("  ports             	list of ports separated by comma") 
    print("  -o             	output the IP with open ports to file")
    print("  -t             	concurrent threads (default 10)")
    print("  -d             	delay between requests in seconds (default 0)")
    print("  -v             	verbose to display closed ports (default False)")
    print("  -h             	display help")
    sys.exit()

if len(sys.argv) <= 2 :
    print("[!] Not enough parameters found. Aborting.")
    help()
    
if "-h" in sys.argv:
    help()

arg = sys.argv[1]
print("*** Scanning range " + arg + " ***")

VERBOSE = False 	# False : TO DISPLAY ONLY OPEN PORTS
DELAY = 0		# DELAY BETWEEN REQUESTS (SECONDS)
MAX_WORKERS = 10    	# MAX CONCURRENT REQUESTS
OUTPUT_FILE = '-o' in sys.argv
RANDOM_DELAY = False

arg2 = sys.argv[2]
ports = arg2.split(",")

try:
    for i in range (0,len(sys.argv)):
        argument = sys.argv[i]
        if argument == "-v":
            VERBOSE = True
        if argument == "-d":
            DELAY = str(sys.argv[i+1])
            if "-" in DELAY:
                DELAY_MIN = DELAY.split("-")[0]
                DELAY_MAX = DELAY.split("-")[1]
                DELAY_MIN = int(DELAY_MIN)
                DELAY_MAX = int(DELAY_MAX)
                if not DELAY_MIN <= DELAY_MAX:
                    print("[-] Please set a valid delay such as -d 2 or -d 3-11")
                    help()
                RANDOM_DELAY = True
            else:
                 DELAY = int(DELAY)
        if argument == "-t":
            MAX_WORKERS = int(sys.argv[i+1])
except:
    print("[-] Please check your arguments")
    help()

if DELAY != 0:
    MAX_WORKERS = 1

print("[i] Using " + str(MAX_WORKERS) + " threads")
if not RANDOM_DELAY:
    print("[i] Using " + str(DELAY) + " seconds delay")
else:
    print("[i] Using " + str(DELAY) + " seconds delay (random)")
print("[i] Save output: " + str(OUTPUT_FILE))
print("[i] Verbose mode: " + str(VERBOSE))

RESULTS_IP = {}
for port in ports:
    RESULTS_IP[port] = []

def getDelay():
    if RANDOM_DELAY:
        return random.randrange(DELAY_MIN,DELAY_MAX,1)
    else:
        return DELAY

def scan_ip(ip_address):
    print("")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        result = sock.connect_ex((ip_address, int(port)))
        if result == 0:
            print(f"[+] PORT OPEN on {ip_address}:{port}")
            RESULTS_IP[port].append(ip_address)
        else:
            if VERBOSE:
                print(f"[-] PORT CLOSED on {ip_address}:{port}")
        sock.close()
        time.sleep(getDelay())
    
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
            print(f"[-] {arg} is not a valid IP address, network in CIDR notation, or file")
            print("Aborting...")
            sys.exit()

print("")
print("--------------------------------")
print("----------- RESULT -------------")
print("--------------------------------")


for key in RESULTS_IP.keys():
    if len(RESULTS_IP[key]) == 0:
        if VERBOSE:
            print(f"\n[-] All ports {key} are closed/filtered")
    else:
        print(f"\n[+] MACHINES WITH PORT {key} OPEN")
        for ip in RESULTS_IP[key]:
                print(ip)
                if OUTPUT_FILE:
                    with open(f"output_pyscan_port_{key}.txt", "a") as file:
                        file.write(ip+"\n")
                    file.close()
                    
if OUTPUT_FILE:
    print("\n[i] Saved results to output_pyscan_port_<port>.txt")
    
print("\n[-] All other ports are closed/filtered")
