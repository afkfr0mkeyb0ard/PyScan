## PyScan
Fast TCP port scanner in Python

### Command
```
> python3 pyscan.py target ports [-o]
target      single IP, range or file of IP
ports       list of ports separated by comma 
-o          output the results ordered by open port (ports_80.txt, ...)
```

### Examples
```
# Scan for open ports 80 and 443 on an IP range [with output]
> python3 pyscan.py 192.168.0.0/24 80,443 -o

# Scan for open port 445 on a single IP
> python3 pyscan.py 192.168.0.123 445

# Scan for open ports 135,139,3389 on a list of IP
> python3 pyscan.py IPS.txt 135,139,3389

# Scan most common ports on a list of IP
> python3 pyscan.py IPS.txt 7,20,21,22,23,25,53,69,80,81,88,102,111,135,139,143,161,179,381,383,389,443,445,464,465,587,593,636,691,902,989,990,993,995,1025,1194,1337,1352,1433,1521,1522,1723,1589,1725,2049,2082,2083,2301,2381,2483,2484,2967,3074,3128,3260,3268,3306,3389,3724,3999,4664,4848,5000,5005,5432,5601,5666,5800,5900,5901,5985,5986,6000,6665,6881,6970,6999,7001,7002,8000,8080,8081,8082,8086,8087,8100,8222,8443,8453,8787,8788,8888,9001,9100,9200,9443,9875,9999,10000,12345,18000,27017,27374,28038,30024,31337,50000
```
