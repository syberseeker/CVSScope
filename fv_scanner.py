import nmap
import signal
from tabulate import tabulate
from colorama import init, Fore, Style

def signal_handler(sig, frame):
    # Function to catch CTR+C and terminate.
    print("\n[*] Fast Vuln Scanner is terminating...\n")
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

                        Fast Vuln Scanner v1.0 by SyberSeeker

------------------------------------------------------------------------------------------

This is simple vulnerability scanner which leverages on TCP SYN (Stealth) method via Nmap.
    
    """ + Style.RESET_ALL
    )

    print(logo)
    

def vulnerability_scan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-sS -sV --script vulners')

    vuln_info = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                if 'vulners' in nm[host][proto][port]:
                    vulns = nm[host][proto][port]['vulners']
                    for vuln in vulns:
                        vuln_info.append([host, port, vuln['id'], vuln['summary']])
    return vuln_info

def detect_os(target_ip):
    """
    Detect the operating system running on the target IP.
    """
    scanner = nmap.PortScanner()
    scanner.scan(target_ip, arguments='-A')
    return scanner[target_ip]['osmatch']

def print_table(data, headers):
    print(tabulate(data, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    target_ip = input("Enter target IP address for scan: ")

    # Displaying OS detection result
    print("\nDetecting OS...")
    os_info = detect_os(target_ip)
    if os_info:
        print("\nDetected OS:")
        for os in os_info:
            print(f"OS Name: {os['name']}")

    # Displaying the scan result in a table format
    vuln_info = vulnerability_scan(target_ip)
    print("\nVulnerability Scan Results:")
    print_table(vuln_info, headers=["IP Address", "Port", "Vulnerability ID", "Summary"])

    # Check if the user wants to save output to a CSV file
csv_output = input("\nWould you like to save the output to a CSV file? (yes/no): ")
if csv_output.lower() == 'yes':
    df = pd.DataFrame(table.get_string().split('\n'))
    df.to_csv('output.csv', index=False)
