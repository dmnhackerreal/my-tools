import os
import requests
import sys
import argparse
import time
import socket # For basic DNS lookup
import whois # For WHOIS lookup - install with: pip install python-whois
import xml.etree.ElementTree as ET # For XML sitemap parsing
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
import random

# Initialize Colorama for colored output
init(autoreset=True)

# List of common User-Agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/109.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
]

def get_random_user_agent():
    """Returns a random User-Agent string."""
    return random.choice(USER_AGENTS)

def print_banner():
    """Prints a professional ASCII art banner for the tool."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
█ █▄░█ █▀▀ █▀█ █▀█ █▀▄▀█ ▄▀█ ▀█▀ █ █▀█ █▄░█   █▀▀ ▄▀█ ▀█▀ █░█ █▀▀ █▀█ █▀▀ █▀█
█ █░▀█ █▀░ █▄█ █▀▄ █░▀░█ █▀█ ░█░ █ █▄█ █░▀█   █▄█ █▀█ ░█░ █▀█ ██▄ █▀▄ ██▄ █▀▄

    Enhanced Information Gatherer V2.0 - Comprehensive Reconnaissance Tool
{Style.RESET_ALL}
"""
    print(banner)

def make_request(url, timeout=10, allow_redirects=True):
    """Helper function to make HTTP requests with random User-Agent."""
    headers = {'User-Agent': get_random_user_agent()}
    try:
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
        return response
    except requests.exceptions.RequestException as e:
        # print(f"{Fore.RED}    [ERROR] Request to {url} failed: {e}{Style.RESET_ALL}")
        return None

def get_server_info(url):
    """
    Detects the web server, X-Powered-By, and common security headers from HTTP headers.
    """
    print(f"\n{Fore.BLUE}[+] Gathering Server and Header Information for {url}{Style.RESET_ALL}")
    response = make_request(url)
    if not response:
        print(f"{Fore.RED}    Error: Could not retrieve headers for {url}.{Style.RESET_ALL}")
        return None

    headers = response.headers
    server_info = headers.get('Server', 'N/A')
    x_powered_by = headers.get('X-Powered-By', 'N/A')
    x_generator = headers.get('X-Generator', 'N/A') # Often used by CMS like WordPress

    print(f"{Fore.GREEN}    Server: {server_info}{Style.RESET_ALL}")
    if x_powered_by != 'N/A':
        print(f"{Fore.GREEN}    X-Powered-By: {x_powered_by}{Style.RESET_ALL}")
    if x_generator != 'N/A':
        print(f"{Fore.GREEN}    X-Generator (CMS): {x_generator}{Style.RESET_ALL}")
    
    # Check for common security headers
    print(f"{Fore.BLUE}    [+] Checking Security Headers:{Style.RESET_ALL}")
    security_headers = {
        'Strict-Transport-Security': 'HSTS',
        'X-Frame-Options': 'Clickjacking Protection',
        'X-Content-Type-Options': 'MIME-sniffing Protection',
        'Content-Security-Policy': 'CSP',
        'Referrer-Policy': 'Referrer Control',
        'Permissions-Policy': 'Feature Control' # New standard
    }
    for header, desc in security_headers.items():
        if headers.get(header):
            print(f"{Fore.GREEN}        {desc} ({header}): {headers[header]}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}        {desc} ({header}): Not set{Style.RESET_ALL}")
    
    return {'server': server_info, 'x_powered_by': x_powered_by, 'x_generator': x_generator, 'headers': headers}

def dns_lookup(domain):
    """
    Performs basic DNS lookups for A and AAAA records.
    """
    print(f"\n{Fore.BLUE}[+] Performing DNS Lookup for {domain}{Style.RESET_ALL}")
    try:
        # A records (IPv4)
        ipv4_addresses = socket.gethostbyname_ex(domain)[2]
        if ipv4_addresses:
            print(f"{Fore.GREEN}    A (IPv4) Records:{Style.RESET_ALL}")
            for ip in ipv4_addresses:
                print(f"{Fore.GREEN}        {ip}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}    No A (IPv4) records found.{Style.RESET_ALL}")

        # AAAA records (IPv6)
        # socket.getaddrinfo can return both IPv4 and IPv6, filter for AF_INET6
        ipv6_addresses = [res[4][0] for res in socket.getaddrinfo(domain, None, socket.AF_INET6)]
        if ipv6_addresses:
            print(f"{Fore.GREEN}    AAAA (IPv6) Records:{Style.RESET_ALL}")
            for ip in ipv6_addresses:
                print(f"{Fore.GREEN}        {ip}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}    No AAAA (IPv6) records found.{Style.RESET_ALL}")

    except socket.gaierror as e:
        print(f"{Fore.RED}    Error performing DNS lookup for {domain}: {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}    An unexpected error occurred during DNS lookup: {e}{Style.RESET_ALL}")

def whois_lookup(domain):
    """
    Performs a WHOIS lookup for the target domain.
    """
    print(f"\n{Fore.BLUE}[+] Performing WHOIS Lookup for {domain}{Style.RESET_ALL}")
    try:
        w = whois.whois(domain)
        if w.registrar:
            print(f"{Fore.GREEN}    Registrar: {w.registrar}{Style.RESET_ALL}")
        if w.creation_date:
            print(f"{Fore.GREEN}    Creation Date: {w.creation_date}{Style.RESET_ALL}")
        if w.expiration_date:
            print(f"{Fore.GREEN}    Expiration Date: {w.expiration_date}{Style.RESET_ALL}")
        if w.name_servers:
            print(f"{Fore.GREEN}    Name Servers:{Style.RESET_ALL}")
            for ns in w.name_servers:
                print(f"{Fore.GREEN}        {ns}{Style.RESET_ALL}")
        # Print all available WHOIS data (can be verbose)
        # print(f"{Fore.YELLOW}    Full WHOIS Data:\n{w}{Style.RESET_ALL}") 
    except whois.parser.PywhoisError as e:
        print(f"{Fore.YELLOW}    WHOIS lookup failed for {domain}: {e}. (Domain might not exist or WHOIS query limited){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}    An unexpected error occurred during WHOIS lookup: {e}{Style.RESET_ALL}")

def parse_robots_txt(base_url):
    """
    Fetches and parses robots.txt for disallowed paths and sitemap links.
    """
    print(f"\n{Fore.BLUE}[+] Parsing robots.txt for {base_url}{Style.RESET_ALL}")
    robots_url = urljoin(base_url, '/robots.txt')
    response = make_request(robots_url, timeout=5)

    if not response or response.status_code != 200:
        print(f"{Fore.YELLOW}    robots.txt not found or inaccessible at {robots_url}.{Style.RESET_ALL}")
        return {'disallowed': [], 'sitemaps': []}

    disallowed_paths = []
    sitemap_links = []
    for line in response.text.splitlines():
        line = line.strip()
        if line.lower().startswith('disallow:'):
            path = line[len('disallow:'):].strip()
            if path and path != '/': # Ignore disallow for root
                disallowed_paths.append(urljoin(base_url, path))
        elif line.lower().startswith('sitemap:'):
            sitemap_links.append(line[len('sitemap:'):].strip())
    
    if disallowed_paths:
        print(f"{Fore.GREEN}    Disallowed Paths (from robots.txt):{Style.RESET_ALL}")
        for path in disallowed_paths:
            print(f"{Fore.GREEN}        {path}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}    No 'Disallow' directives found for User-agent: *.{Style.RESET_ALL}")

    if sitemap_links:
        print(f"{Fore.GREEN}    Sitemap Links (from robots.txt):{Style.RESET_ALL}")
        for sitemap_link in sitemap_links:
            print(f"{Fore.GREEN}        {sitemap_link}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}    No 'Sitemap' links found in robots.txt.{Style.RESET_ALL}")
            
    return {'disallowed': disallowed_paths, 'sitemaps': sitemap_links}

def parse_sitemap(sitemap_url):
    """
    Fetches and parses an XML sitemap (or sitemap index) for URLs.
    Handles sitemap indexes recursively.
    """
    all_urls = []
    print(f"{Fore.BLUE}    [+] Parsing sitemap: {sitemap_url}{Style.RESET_ALL}")
    try:
        response = make_request(sitemap_url, timeout=10)
        if not response or response.status_code != 200:
            print(f"{Fore.YELLOW}        Could not fetch sitemap at {sitemap_url}. Status: {response.status_code if response else 'N/A'}{Style.RESET_ALL}")
            return []

        root = ET.fromstring(response.content)
        namespaces = {
            'sitemap': 'http://www.sitemaps.org/schemas/sitemap/0.9',
            'news': 'http://www.google.com/schemas/sitemap-news/0.9',
            'image': 'http://www.google.com/schemas/sitemap-image/1.1',
            'video': 'http://www.google.com/schemas/sitemap-video/1.1',
        }

        # Check if it's a sitemap index (contains <sitemap> tags)
        if root.tag == '{http://www.sitemaps.org/schemas/sitemap/0.9}sitemapindex':
            for sitemap_tag in root.findall('sitemap:sitemap', namespaces):
                loc = sitemap_tag.find('sitemap:loc', namespaces)
                if loc is not None:
                    # Recursively parse nested sitemaps
                    all_urls.extend(parse_sitemap(loc.text))
        # Otherwise, it's a regular sitemap (contains <url> tags)
        elif root.tag == '{http://www.sitemaps.org/schemas/sitemap/0.9}urlset':
            for url_tag in root.findall('sitemap:url', namespaces):
                loc = url_tag.find('sitemap:loc', namespaces)
                if loc is not None:
                    all_urls.append(loc.text)
        else:
            print(f"{Fore.YELLOW}        Unknown sitemap format for {sitemap_url}. Root tag: {root.tag}{Style.RESET_ALL}")

    except ET.ParseError as e:
        print(f"{Fore.RED}        Error parsing XML sitemap at {sitemap_url}: {e}{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}        Network error fetching sitemap {sitemap_url}: {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}        An unexpected error occurred during sitemap parsing: {e}{Style.RESET_ALL}")
    
    return all_urls

def enumerate_subdomains(domain, wordlist_path, num_workers=10):
    """
    Attempts to find subdomains using a wordlist with concurrency.
    """
    found_subdomains = []
    print(f"\n{Fore.BLUE}[+] Enumerating Subdomains for {domain} using wordlist: {wordlist_path}{Style.RESET_ALL}")
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}    Error: Subdomain wordlist not found at {wordlist_path}. Skipping subdomain enumeration.{Style.RESET_ALL}")
        return []

    print(f"{Fore.YELLOW}    Trying {len(subdomains)} common subdomains with {num_workers} workers...{Style.RESET_ALL}")
    
    def check_subdomain(sub):
        target_url = f"http://{sub}.{domain}"
        response = make_request(target_url, timeout=5, allow_redirects=True)
        if response and response.status_code in [200, 301, 302]:
            print(f"{Fore.GREEN}    Found Subdomain: {target_url} (Status: {response.status_code}){Style.RESET_ALL}")
            return target_url
        return None

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(check_subdomain, sub) for sub in subdomains]
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            if result:
                found_subdomains.append(result)
            # Update progress indicator
            sys.stdout.write(f"\r    Processed {i+1}/{len(subdomains)} subdomains...{Style.RESET_ALL}")
            sys.stdout.flush()
    print("") # Newline after progress
    
    if not found_subdomains:
        print(f"{Fore.YELLOW}    No subdomains found with the provided wordlist.{Style.RESET_ALL}")
    return found_subdomains

def find_hidden_paths(base_url, wordlist_path, num_workers=10):
    """
    Attempts to find hidden directories and files using a wordlist with concurrency.
    """
    found_paths = []
    print(f"\n{Fore.BLUE}[+] Searching for Hidden Directories and Files on {base_url} using wordlist: {wordlist_path}{Style.RESET_ALL}")
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            paths = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}    Error: Path wordlist not found at {wordlist_path}. Skipping directory/file search.{Style.RESET_ALL}")
        return []

    print(f"{Fore.YELLOW}    Trying {len(paths)} common paths with {num_workers} workers...{Style.RESET_ALL}")

    def check_path(path):
        target_url = urljoin(base_url, path)
        response = make_request(target_url, timeout=5, allow_redirects=True)
        if response and response.status_code in [200, 301, 302, 401, 403]: # Interesting status codes
            print(f"{Fore.GREEN}    Found Path: {target_url} (Status: {response.status_code}){Style.RESET_ALL}")
            return target_url
        return None

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(check_path, path) for path in paths]
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            if result:
                found_paths.append(result)
            # Update progress indicator
            sys.stdout.write(f"\r    Processed {i+1}/{len(paths)} paths...{Style.RESET_ALL}")
            sys.stdout.flush()
    print("") # Newline after progress

    if not found_paths:
        print(f"{Fore.YELLOW}    No interesting paths found with the provided wordlist.{Style.RESET_ALL}")
    return found_paths

if __name__ == "__main__":
    print_banner()

    parser = argparse.ArgumentParser(description="Enhanced Information Gatherer - Comprehensive Reconnaissance Tool.")
    parser.add_argument("target", help="Target URL (e.g., http://example.com) or Domain (e.g., example.com).")
    parser.add_argument("-sw", "--subdomain_wordlist", default="common_subdomains.txt", 
                        help="Path to the wordlist file for subdomain enumeration (default: common_subdomains.txt).")
    parser.add_argument("-pw", "--path_wordlist", default="common_paths.txt",
                        help="Path to the wordlist file for directory/file enumeration (default: common_paths.txt).")
    parser.add_argument("-w", "--workers", type=int, default=10, 
                        help="Number of concurrent workers for subdomain/path enumeration (default: 10).")

    args = parser.parse_args()

    target_input = args.target

    # Normalize input: if it's just a domain, add http:// for requests
    if not target_input.startswith('http://') and not target_input.startswith('https://'):
        target_url = f"http://{target_input}"
        target_domain = target_input
    else:
        target_url = target_input
        parsed_url = urlparse(target_input)
        target_domain = parsed_url.netloc

    print(f"\n{Fore.CYAN}{Style.BRIGHT}--- Starting Enhanced Information Gathering for: {target_url} ({target_domain}) ---{Style.RESET_ALL}\n")

    # 1. DNS Information
    dns_lookup(target_domain)

    # 2. WHOIS Lookup
    whois_lookup(target_domain)

    # 3. OS and Server Detection
    server_info_data = get_server_info(target_url)

    # 4. Robots.txt Parsing
    robots_data = parse_robots_txt(target_url)
    all_sitemap_urls = list(set(robots_data['sitemaps'])) # Use set to avoid duplicates

    # 5. Sitemap.xml Parsing (if found in robots.txt or default)
    if not all_sitemap_urls: # If no sitemaps found in robots.txt, try default sitemap.xml
        default_sitemap = urljoin(target_url, '/sitemap.xml')
        response_default_sitemap = make_request(default_sitemap, timeout=5)
        if response_default_sitemap and response_default_sitemap.status_code == 200:
            print(f"\n{Fore.BLUE}[+] Default sitemap.xml found at {default_sitemap}{Style.RESET_ALL}")
            all_sitemap_urls.append(default_sitemap)
        else:
            default_sitemap_index = urljoin(target_url, '/sitemap_index.xml')
            response_default_sitemap_index = make_request(default_sitemap_index, timeout=5)
            if response_default_sitemap_index and response_default_sitemap_index.status_code == 200:
                print(f"\n{Fore.BLUE}[+] Default sitemap_index.xml found at {default_sitemap_index}{Style.RESET_ALL}")
                all_sitemap_urls.append(default_sitemap_index)

    if all_sitemap_urls:
        print(f"\n{Fore.BLUE}[+] Parsing Sitemaps...{Style.RESET_ALL}")
        all_found_urls_from_sitemaps = []
        for s_url in all_sitemap_urls:
            all_found_urls_from_sitemaps.extend(parse_sitemap(s_url))
        
        if all_found_urls_from_sitemaps:
            print(f"{Fore.GREEN}    Total unique URLs found from sitemaps: {len(set(all_found_urls_from_sitemaps)):,}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}    No URLs extracted from sitemaps.{Style.RESET_ALL}")

    # Create dummy wordlists if not provided or found (for initial testing)
    # In a real scenario, these should be large and comprehensive
    if not os.path.exists(args.subdomain_wordlist):
        print(f"{Fore.YELLOW}\n[!] Warning: Subdomain wordlist '{args.subdomain_wordlist}' not found. Creating a small default for demonstration.{Style.RESET_ALL}")
        with open(args.subdomain_wordlist, 'w') as f:
            f.write("www\nmail\ndev\nblog\ntest\nadmin\napi\nshop\nbeta\nforum\n")
    
    if not os.path.exists(args.path_wordlist):
        print(f"{Fore.YELLOW}\n[!] Warning: Path wordlist '{args.path_wordlist}' not found. Creating a small default for demonstration.{Style.RESET_ALL}")
        with open(args.path_wordlist, 'w') as f:
            f.write("admin/\nlogin.php\ndashboard/\nwp-admin/\n.git/\n.env\nbackup/\ntest.php\nrobots.txt\nsitemap.xml\nREADME.md\nindex.php\n")


    # 6. Subdomain Enumeration
    enumerate_subdomains(target_domain, args.subdomain_wordlist, args.workers)

    # 7. Search Directories and Files
    find_hidden_paths(target_url, args.path_wordlist, args.workers)

    print(f"\n{Fore.CYAN}{Style.BRIGHT}--- Enhanced Information Gathering Complete ---{Style.RESET_ALL}")
    print(f"{Fore.RED}Remember: This tool is for educational purposes only. Unauthorized scanning is illegal and unethical.{Style.RESET_ALL}")

