# CVSScope

This is my first hobby project to experiment the CVSS scoring and OSSTMM scoring using nmap module. This simple tool will perform the vulnerability scan by entering the target IP and the result can be export in the CSV format.


# Installation

- ***pip install nmap***
- ***pip install tabulate***
- ***pip install colorama***
- ***pip install signal***
- ***pip install pandas***

# How to Use

- Just run ***python3 cvsscope_v2.py***

# Version

v1.0 Fast Vuln Scanner (2024-02-28)
- Adding in Script vulners ✅
- Displaying the scan result in a table format ✅
- Ability to export the scan result in the CSV format ✅

v2.0 Fast Vuln Scanner (2024-07-30)
- Allowing IP range scan instead of single IP ✅
- Changing from CVSS v3.0 to CVSS v4.0 scoring ✅

v3.0 (2025-02-02)
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

# Next Roadmap v3.0

- Adding capability to perform attack surface discovery
- Adding capability to classify attack surface types

