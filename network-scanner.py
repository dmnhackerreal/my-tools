import nmap
import ipaddress
import sys
from colorama import Fore, Style, init

# Initialize Colorama for colored output
init(autoreset=True)

def print_banner():
    """Prints a simple, readable ASCII art banner for the tool."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
█▄░█ █▀▀ ▀█▀ █░█░█ █▀█ █▀█ █▄▀   █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█
█░▀█ ██▄ ░█░ ▀▄▀▄▀ █▄█ █▀▄ █░█   ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄
                                            V1.0 - A Powerful Port and Service Scanner
{Style.RESET_ALL}
"""
    print(banner)

def scan_network_ports(ip_range, ports='1-1024'):
    """
    Scans a given IP range for open ports and services.

    Args:
        ip_range (str): The IP address or range to scan (e.g., '192.168.1.0/24', '192.168.1.100').
        ports (str): A string representing the ports to scan (e.g., '22,80,443' or '1-1024').
    """
    nm = nmap.PortScanner()
    print(f"{Fore.BLUE}{Style.BRIGHT}Starting network scan for IP range: {ip_range} on ports: {ports}{Style.RESET_ALL}\n")

    try:
        # Validate IP range
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        print(f"{Fore.RED}Error: Invalid IP range '{ip_range}'. Please provide a valid IP address or CIDR range.{Style.RESET_ALL}")
        return

    hosts_found = False
    for host in network.hosts():
        host_str = str(host)
        print(f"{Fore.YELLOW}Scanning host: {host_str}...{Style.RESET_ALL}")
        try:
            # -T4: Aggressive timing template (faster scan)
            # -p: Specify ports
            # -sV: Probe open ports to determine service/version info
            nm.scan(host_str, ports, arguments='-T4 -sV')
        except nmap.PortScannerError as e:
            print(f"{Fore.RED}Error scanning {host_str}: {e}{Style.RESET_ALL}")
            continue

        if host_str in nm.all_hosts():
            hosts_found = True
            print(f"\n{Fore.GREEN}{Style.BRIGHT}--- Host: {host_str} ({nm[host_str].hostname()}) ---{Style.RESET_ALL}")
            if nm[host_str].state() == 'up':
                print(f"  {Fore.GREEN}Status: {nm[host_str].state()}{Style.RESET_ALL}")
                for proto in nm[host_str].all_protocols():
                    print(f"  {Fore.MAGENTA}Protocol: {proto}{Style.RESET_ALL}")
                    lport = nm[host_str][proto].keys()
                    sorted_lport = sorted(lport)
                    for port in sorted_lport:
                        port_info = nm[host_str][proto][port]
                        if port_info['state'] == 'open':
                            print(f"    {Fore.LIGHTGREEN_EX}Port: {port}\tState: {port_info['state']}\tService: {port_info['name']}\tVersion: {port_info['version']}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.YELLOW}Status: {nm[host_str].state()} (Host might be down or blocked){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}No results for {host_str} (Host might be down or not responding to scan){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'-' * 40}{Style.RESET_ALL}")

    if not hosts_found:
        print(f"\n{Fore.RED}No active hosts or open ports found in the specified range.{Style.RESET_ALL}")

if __name__ == "__main__":
    print_banner() # Call the banner function at the start
    if len(sys.argv) < 2:
        print(f"{Fore.RED}Usage: python network_scanner.py <IP_Range> [Ports]{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Example: python network_scanner.py 192.168.1.0/24{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Example: python network_scanner.py 192.168.1.100 22,80,443{Style.RESET_ALL}")
        sys.exit(1)

    ip_range_arg = sys.argv[1]
    ports_arg = sys.argv[2] if len(sys.argv) > 2 else '1-1024' # Default to common ports

    scan_network_ports(ip_range_arg, ports_arg)
