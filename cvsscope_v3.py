import nmap
import signal
from tabulate import tabulate
from colorama import init, Fore, Style
import pandas as pd

def signal_handler(sig, frame):
    print("\n[*] CVSScope is terminating...\n")
    exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    init()

    RED, WHITE, GREEN, END, YELLOW, BOLD = (
        "\033[91m",
        "\33[97m",
        "\033[1;32m",
        "\033[0m",
        "\33[93m",
        "\033[1m",
    )

    logo = (
        Style.BRIGHT + Fore.GREEN +
        """
        ------------------------------------------------------------------------------------------
        CVSScope v3.0 by SyberSeeker (CVSS v4.0 and OSSTMM Score Integrated)
        ------------------------------------------------------------------------------------------
        This is an experimental vulnerability scanner leveraging the TCP SYN (Stealth) method via Nmap.
        Now supports CVSS v4.0 severity mapping and OSSTMM Scoring Metric with enhanced firewall evasion techniques.
        """ + Style.RESET_ALL
    )

    print(logo)

    CVSS_SEVERITY = {
        "none": "None (0.0)",
        "low": "Low (0.1 - 3.9)",
        "medium": "Medium (4.0 - 6.9)",
        "high": "High (7.0 - 8.9)",
        "critical": "Critical (9.0 - 10.0)"
    }

    OSSTMM_METRICS = {
        "none": "Visibility",
        "low": "Trust",
        "medium": "Access Control",
        "high": "Skill Level",
        "critical": "Motivation"
    }

    def map_cvss_v4(score):
        try:
            score = float(score)
        except ValueError:
            return "unknown"
        
        if score == 0.0:
            return "none"
        elif 0.1 <= score <= 3.9:
            return "low"
        elif 4.0 <= score <= 6.9:
            return "medium"
        elif 7.0 <= score <= 8.9:
            return "high"
        elif 9.0 <= score <= 10.0:
            return "critical"
        return "unknown"

    def check_vulners_script():
        nm = nmap.PortScanner()
        try:
            nm.scan(arguments="--script vulners")
        except nmap.PortScannerError:
            print(f"{RED}[!] 'vulners' script not found! Install it before running this scan.{END}")
            exit(1)

    def vulnerability_scan(ip_range, stealth_mode=True):
        nm = nmap.PortScanner()
        scan_arguments = "-sS -T1 --script vulners"
        
        if stealth_mode:
            scan_arguments += " -D RND:10 -f --mtu 16 -g 53"

        print(f"\n[*] Running scan with arguments: {scan_arguments}")

        nm.scan(ip_range, arguments=scan_arguments)
        
        vuln_info = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if 'script' in nm[host][proto][port]:
                        vulners = nm[host][proto][port]['script'].get('vulners', {})
                        if isinstance(vulners, dict):
                            for vuln_id, vuln_data in vulners.items():
                                cvss_score = vuln_data.get('cvss', {}).get('score', '0.0')
                                severity = map_cvss_v4(cvss_score)
                                summary = vuln_data.get('title', 'No summary available')
                                osstmm_score = OSSTMM_METRICS.get(severity, "Unknown")
                                vuln_info.append([host, port, vuln_id, summary, CVSS_SEVERITY.get(severity, "unknown"), cvss_score, osstmm_score])
        
        return vuln_info

    def detect_os(ip_range):
        scanner = nmap.PortScanner()
        scanner.scan(ip_range, arguments='-A')
        return {host: scanner[host].get('osmatch', []) for host in scanner.all_hosts()}

    def print_table(data, headers):
        print(tabulate(data, headers=headers, tablefmt="grid"))

    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")

    print("\n[*] Checking 'vulners' script availability...")
    check_vulners_script()

    print("\n[*] Detecting OS...")
    os_info = detect_os(ip_range)

    if os_info:
        print("\n[*] Detected OS:")
        for host, os_list in os_info.items():
            for os in os_list:
                print(f"Host: {host} - OS Name: {os['name']}")
    else:
        print(f"{RED}[!] No OS detected. The scan may be incomplete.{END}")

    stealth_mode = input("\n[*] Enable stealth mode? (yes/no): ").strip().lower()
    stealth_mode = stealth_mode if stealth_mode in ['yes', 'no'] else 'yes'
    stealth_mode = stealth_mode == 'yes'

    vuln_info = vulnerability_scan(ip_range, stealth_mode)
    
    print("\n[*] Vulnerability Scan Results:")
    print_table(vuln_info, headers=["IP Address", "Port", "Vulnerability ID", "Summary", "Severity", "CVSS Score", "OSSTMM Score"])

    csv_output = input("\n[*] Would you like to save the output to a CSV file? (yes/no): ")
    
    if csv_output.lower() == 'yes':
        df = pd.DataFrame(vuln_info, columns=["IP Address", "Port", "Vulnerability ID", "Summary", "Severity", "CVSS Score", "OSSTMM Score"])
        df.to_csv('output.csv', index=False)
        print(f"{GREEN}[*] Output saved to 'output.csv'.{END}")
