import requests
import sys
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init

# Initialize Colorama for colored output
init(autoreset=True)

def print_banner():
    """Prints a simple, readable ASCII art banner for the tool."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
█ █▄░█ █▀▀ █▀█ █▀█ █▀▄▀█ ▄▀█ ▀█▀ █ █▀█ █▄░█   █▀▀ ▄▀█ ▀█▀ █░█ █▀▀ █▀█ █▀▀ █▀█
█ █░▀█ █▀░ █▄█ █▀▄ █░▀░█ █▀█ ░█░ █ █▄█ █░▀█   █▄█ █▀█ ░█░ █▀█ ██▄ █▀▄ ██▄ █▀▄

   Information Gatherer V1.0 - Passive Reconnaissance Tool
{Style.RESET_ALL}
"""
    print(banner)

def get_server_info(url):
    """
    Detects the web server and potentially the operating system from HTTP headers.
    Args:
        url (str): The target URL.
    Returns:
        dict: A dictionary containing server and OS information, or None if an error occurs.
    """
    print(f"{Fore.BLUE}[+] Gathering Server Information for {url}{Style.RESET_ALL}")
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        server_info = headers.get('Server')
        x_powered_by = headers.get('X-Powered-By')
        os_info = headers.get('X-AspNet-Version') or headers.get('X-Generator') # Simple OS/framework guess

        print(f"{Fore.GREEN}    Server: {server_info if server_info else 'N/A'}{Style.RESET_ALL}")
        if x_powered_by:
            print(f"{Fore.GREEN}    X-Powered-By: {x_powered_by}{Style.RESET_ALL}")
        if os_info:
            print(f"{Fore.GREEN}    Potential OS/Framework: {os_info}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}    Potential OS/Framework: Cannot determine from headers.{Style.RESET_ALL}")
        return {'server': server_info, 'x_powered_by': x_powered_by, 'os_info': os_info}
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}    Error gathering server info: {e}{Style.RESET_ALL}")
        return None

def enumerate_subdomains(domain, wordlist_path='common_subdomains.txt'):
    """
    Attempts to find subdomains using a wordlist.
    Args:
        domain (str): The target domain (e.g., 'example.com').
        wordlist_path (str): Path to a file containing common subdomain names.
    Returns:
        list: A list of found subdomains.
    """
    found_subdomains = []
    print(f"\n{Fore.BLUE}[+] Enumerating Subdomains for {domain} using wordlist: {wordlist_path}{Style.RESET_ALL}")
    try:
        with open(wordlist_path, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}    Error: Subdomain wordlist not found at {wordlist_path}. Skipping subdomain enumeration.{Style.RESET_ALL}")
        return []

    print(f"{Fore.YELLOW}    Trying {len(subdomains)} common subdomains...{Style.RESET_ALL}")
    for sub in subdomains:
        target_url = f"http://{sub}.{domain}"
        try:
            response = requests.get(target_url, timeout=5, allow_redirects=True)
            if response.status_code in [200, 301, 302]:
                print(f"{Fore.GREEN}    Found Subdomain: {target_url} (Status: {response.status_code}){Style.RESET_ALL}")
                found_subdomains.append(target_url)
        except requests.exceptions.ConnectionError:
            # Common for non-existent subdomains, suppress detailed error
            pass
        except requests.exceptions.RequestException as e:
            # Other request errors
            print(f"{Fore.YELLOW}    Error checking {target_url}: {e}{Style.RESET_ALL}")
            pass # Keep trying other subdomains
    if not found_subdomains:
        print(f"{Fore.YELLOW}    No subdomains found with the provided wordlist.{Style.RESET_ALL}")
    return found_subdomains

def find_hidden_paths(base_url, wordlist_path='common_paths.txt'):
    """
    Attempts to find hidden directories and files using a wordlist.
    Args:
        base_url (str): The base URL of the target (e.g., 'http://example.com').
        wordlist_path (str): Path to a file containing common directory and file names.
    Returns:
        list: A list of found paths.
    """
    found_paths = []
    print(f"\n{Fore.BLUE}[+] Searching for Hidden Directories and Files on {base_url} using wordlist: {wordlist_path}{Style.RESET_ALL}")
    try:
        with open(wordlist_path, 'r') as f:
            paths = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}    Error: Path wordlist not found at {wordlist_path}. Skipping directory/file search.{Style.RESET_ALL}")
        return []

    print(f"{Fore.YELLOW}    Trying {len(paths)} common paths...{Style.RESET_ALL}")
    for path in paths:
        target_url = urljoin(base_url, path)
        try:
            response = requests.get(target_url, timeout=5, allow_redirects=True)
            if response.status_code in [200, 301, 302, 401, 403]: # Interesting status codes
                print(f"{Fore.GREEN}    Found Path: {target_url} (Status: {response.status_code}){Style.RESET_ALL}")
                found_paths.append(target_url)
        except requests.exceptions.ConnectionError:
            # Common for non-existent paths, suppress detailed error
            pass
        except requests.exceptions.RequestException as e:
            # Other request errors
            print(f"{Fore.YELLOW}    Error checking {target_url}: {e}{Style.RESET_ALL}")
            pass # Keep trying other paths
    if not found_paths:
        print(f"{Fore.YELLOW}    No interesting paths found with the provided wordlist.{Style.RESET_ALL}")
    return found_paths

if __name__ == "__main__":
    print_banner()

    if len(sys.argv) < 2:
        print(f"{Fore.RED}Usage: python information-gatherer.py <Target_URL_or_Domain>{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Example (URL): python information-gatherer.py http://example.com{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Example (Domain): python information-gatherer.py example.com{Style.RESET_ALL}")
        sys.exit(1)

    target_input = sys.argv[1]

    # Normalize input: if it's just a domain, add http:// for requests
    if not target_input.startswith('http://') and not target_input.startswith('https://'):
        target_url = f"http://{target_input}"
        target_domain = target_input
    else:
        target_url = target_input
        parsed_url = urlparse(target_input)
        target_domain = parsed_url.netloc

    print(f"\n{Fore.CYAN}{Style.BRIGHT}--- Starting Information Gathering for: {target_url} ---{Style.RESET_ALL}\n")

    # 1. OS and Server Detection
    get_server_info(target_url)

    # Create dummy wordlists for demonstration
    # In a real scenario, you'd use much larger and more specific wordlists
    with open('common_subdomains.txt', 'w') as f:
        f.write("www\nmail\ndev\nblog\ntest\nadmin\napi\nshop\nbeta\nforum\n")
    with open('common_paths.txt', 'w') as f:
        f.write("admin/\nlogin.php\ndashboard/\nwp-admin/\n.git/\n.env\nbackup/\ntest.php\nrobots.txt\nsitemap.xml\n")

    # 2. Subdomain Enumeration
    enumerate_subdomains(target_domain, 'common_subdomains.txt')

    # 3. Search Directories and Files
    find_hidden_paths(target_url, 'common_paths.txt')

    print(f"\n{Fore.CYAN}{Style.BRIGHT}--- Information Gathering Complete ---{Style.RESET_ALL}")
    print(f"{Fore.RED}Remember: This tool is for educational purposes only. Unauthorized scanning is illegal.{Style.RESET_ALL}")

