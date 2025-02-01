# CVSScope

This is my first hobby project to experiment the CVSS scoring and OSSTMM scoring using nmap module. This simple tool will perform the vulnerability scan by entering the target IP and the result can be export in the CSV format.

# Installation

- ***pip install nmap***
- ***pip install tabulate***
- ***pip install colorama***
- ***pip install signal***
- ***pip install pandas***

# How to Use

- Download ***cvsscope_v3.py*** from this repository and run ***python3 cvsscope_v3.py***

# Version

**v3.0 CVSScope (2025-02-02)**
- Renaming this project from Fast Vuln Scanner to CVSScope ✅
- Replacing python-nmap module with nmap module ✅
- Vulners script check ✅
- Multi-host OS detection ✅
- Stealth mode selection with input validation ✅
- Detailed vulnerability scan results ✅
- CVSS v4.0 severity mapping + OSSTMM scores ✅
- Handles cases where no vulnerabilities or OS information is found ✅
- Allows saving scan results to CSV ✅

Nmap Arguments Improvement:
- Uses -sS (Stealth SYN Scan) to reduce detection by IDS ✅
- Includes -T1 (Slow Scan Timing) to lower detectability ✅
- Decoy Scanning (-D RND:10) is correctly implemented for anonymity ✅
- Packet Fragmentation (-f --mtu 16) may help bypass packet inspection ✅
- Source Port Manipulation (-g 53) to evade filtering ✅

**v2.0 Fast Vuln Scanner (2024-07-30)**
- Allowing IP range scan instead of single IP ✅
- Changing from CVSS v3.0 to CVSS v4.0 scoring ✅

**v1.0 Fast Vuln Scanner (2024-02-28)**
- Adding in Script vulners ✅
- Displaying the scan result in a table format ✅
- Ability to export the scan result in the CSV format ✅


# Next Roadmap v3.0

- Adding capability to perform attack surface discovery
- Adding capability to classify attack surface types

# Output Sample

**Startup Prompt**

![image](https://github.com/user-attachments/assets/21ce28f1-17f0-4ab1-b9bb-633ee2782dc2)

**Checking for vulners script**

![image](https://github.com/user-attachments/assets/092a632c-4c86-4e51-bfa6-9cc49b40927b)

**OS Detection**

![image](https://github.com/user-attachments/assets/cc9b0742-3997-451c-b439-4befa0619eca)

**Stealth Mode Selection**

![image](https://github.com/user-attachments/assets/d6dcaac4-8e14-4b59-906b-bcbc7cc5c89c)

**Vulnerability Scan Result**

![image](https://github.com/user-attachments/assets/19cc23ad-9cd8-436a-be5a-c2a48ae96fdb)



