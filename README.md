## PyScan
Fast port scanner for various services

### Command
```
> python3 pyscan.py target ports [-o]
target      single IP, range or file of IP
ports       list of ports separated by comma 
-o          output the IP with open ports to file
```

### Examples
```
# Scan for open ports 80 and 443 on an IP range [with output]
> python3 pyscan.py 192.168.0.0/24 80,443 -o

# Scan for open port 445 on a single IP
> python3 pyscan.py 192.168.0.123 445

# Scan for open ports 135,139,3389 on a list of IP
> python3 pyscan.py IPS.txt 135,139,3389
```
