import requests
import sys
import argparse
import time
import random
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup # For parsing HTML to find forms (optional, for login forms)
from colorama import Fore, Style, init
import re # For basic entropy check

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

# Common Session Cookie Names to look for
SESSION_COOKIE_NAMES = [
    "JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "SESSIONID",
    "session", "connect.sid", "laravel_session", "ci_session", "csrftoken",
    "wp_session", "woocommerce_session" # WordPress/WooCommerce specific
]

def get_random_user_agent():
    """Returns a random User-Agent string."""
    return random.choice(USER_AGENTS)

def print_banner():
    """Prints a professional ASCII art banner for the Session ID Analyzer."""
    banner = f"""
{Fore.GREEN}{Style.BRIGHT}
█ █▀▄   ▄▀█ █▄░█ ▄▀█ █░░ █▄█ ▀█ █▀▀ █▀█
█ █▄▀   █▀█ █░▀█ █▀█ █▄▄ ░█░ █▄ ██▄ █▀▄
Session ID Analyzer V1.0
---------------------------------------------------
{Style.RESET_ALL}
"""
    print(banner)

def make_request(url, method='GET', data=None, params=None, cookies=None, timeout=10, allow_redirects=True):
    """
    Helper function to make HTTP requests with random User-Agent.
    Returns the response object or None on error.
    """
    headers = {'User-Agent': get_random_user_agent()}
    try:
        session = requests.Session()
        session.headers.update(headers)
        if cookies:
            session.cookies.update(cookies)

        if method.upper() == 'POST':
            response = session.post(url, data=data, timeout=timeout, allow_redirects=allow_redirects)
        else: # Default to GET
            response = session.get(url, params=params, timeout=timeout, allow_redirects=allow_redirects)
        return response
    except requests.exceptions.RequestException as e:
        # print(f"{Fore.RED}    [ERROR] Request to {url} failed: {e}{Style.RESET_ALL}")
        return None

def extract_session_id(response_cookies):
    """
    Extracts common session IDs from a requests.cookies.RequestsCookieJar object.
    Returns the first found session ID string or None.
    """
    for cookie_name in SESSION_COOKIE_NAMES:
        if cookie_name in response_cookies:
            return response_cookies[cookie_name]
    return None

def analyze_session_id(session_id):
    """
    Performs basic analysis on a session ID string for randomness and complexity.
    """
    if not session_id:
        return "N/A"

    length = len(session_id)
    unique_chars = len(set(session_id))
    
    # Check for common patterns (very basic heuristic)
    is_numeric = session_id.isdigit()
    is_alphanumeric = session_id.isalnum()
    
    # Simple check for repeating patterns (e.g., 'aaaaaa') or sequential (e.g., '123456')
    has_repeating_chars = any(session_id.count(c) > length / 2 for c in set(session_id))
    has_sequential_patterns = bool(re.search(r'(012|123|abc|bcd)', session_id, re.IGNORECASE)) # Very basic

    analysis = []
    analysis.append(f"Length: {length}")
    analysis.append(f"Unique Characters: {unique_chars}")
    analysis.append(f"Is Numeric: {is_numeric}")
    analysis.append(f"Is Alphanumeric: {is_alphanumeric}")

    if length < 16: # Industry best practice recommends 128-bit (16-byte) random IDs
        analysis.append(f"{Fore.RED}    [WARNING] Short length (less than 16 chars). Potentially weak randomness.{Style.RESET_ALL}")
    if unique_chars < length / 2:
        analysis.append(f"{Fore.YELLOW}    [INFO] Low unique character count. May indicate lower entropy.{Style.RESET_ALL}")
    if is_numeric:
        analysis.append(f"{Fore.RED}    [VULNERABLE] Numeric only. Very weak.{Style.RESET_ALL}")
    if has_repeating_chars:
        analysis.append(f"{Fore.RED}    [WARNING] Repeating character patterns found. Potentially weak.{Style.RESET_ALL}")
    if has_sequential_patterns:
        analysis.append(f"{Fore.RED}    [WARNING] Sequential patterns found. Potentially weak.{Style.RESET_ALL}")
    
    if len(analysis) == 4: # Only basic info, no warnings/vulnerabilities
        return f"{Fore.GREEN}Looks reasonably complex (Length: {length}, Unique Chars: {unique_chars}){Style.RESET_ALL}"
    
    return "\n        ".join(analysis)

def session_id_analyzer(target_url, login_url=None, username=None, password=None, num_attempts=5, delay_per_attempt=1):
    """
    Main function to orchestrate the Session ID analysis.
    """
    print(f"\n{Fore.BLUE}[+] Starting Session ID Analysis for {target_url}...{Style.RESET_ALL}")
    print(f"{Fore.BLUE}    Number of attempts: {num_attempts}, Delay per attempt: {delay_per_attempt}s{Style.RESET_ALL}")

    extracted_sessions = []

    # 1. Analyze Session IDs for anonymous (unauthenticated) requests
    print(f"\n{Fore.BLUE}    [+] Analyzing Session IDs for ANONYMOUS requests...{Style.RESET_ALL}")
    for i in range(num_attempts):
        print(f"        [*] Attempt {i+1}/{num_attempts} (Anonymous)...", end='\r')
        response = make_request(target_url, timeout=10)
        if response:
            session_id = extract_session_id(response.cookies)
            if session_id:
                extracted_sessions.append({'type': 'Anonymous', 'attempt': i+1, 'session_id': session_id})
                print(f"{Fore.GREEN}        [*] Attempt {i+1} (Anonymous): Session ID: {session_id}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}        [-] Attempt {i+1} (Anonymous): No common session cookie found.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}        [-] Attempt {i+1} (Anonymous): Request failed.{Style.RESET_ALL}")
        time.sleep(delay_per_attempt)
    
    # Compare anonymous session IDs
    if extracted_sessions:
        print(f"\n{Fore.BLUE}    [+] Comparing Anonymous Session IDs:{Style.RESET_ALL}")
        first_anon_id = extracted_sessions[0]['session_id'] if extracted_sessions[0]['session_id'] else "N/A"
        all_same = all(s['session_id'] == first_anon_id for s in extracted_sessions if s['type'] == 'Anonymous' and s['session_id'])
        if all_same:
            print(f"{Fore.YELLOW}        [WARNING] All anonymous Session IDs are identical. This might indicate weak session management (e.g., static IDs for unauthenticated users).{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}        All anonymous Session IDs are different (good).{Style.RESET_ALL}")
        
        print(f"{Fore.BLUE}    [+] Basic Analysis of a sample Anonymous Session ID ({first_anon_id}):{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}        {analyze_session_id(first_anon_id)}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}    No anonymous session IDs were found to analyze.{Style.RESET_ALL}")

    # 2. Analyze Session IDs for authenticated requests (if login credentials provided)
    if login_url and username and password:
        print(f"\n{Fore.BLUE}    [+] Attempting to LOG IN to analyze Authenticated Session IDs...{Style.RESET_ALL}")
        
        # This part requires extracting login form details, similar to credential_stuffing_scanner
        response_login_page = make_request(login_url, method='GET')
        if not response_login_page:
            print(f"{Fore.RED}        Error: Could not fetch login page at {login_url}. Cannot proceed with authenticated test.{Style.RESET_ALL}")
            return []
        
        soup = BeautifulSoup(response_login_page.text, 'html.parser')
        login_form = None
        for form_tag in soup.find_all('form'):
            password_input = form_tag.find('input', type='password')
            if password_input:
                form_action = form_tag.get('action') or login_url
                if not urlparse(form_action).netloc: form_action = urljoin(login_url, form_action)
                form_method = form_tag.get('method', 'POST').upper()

                inputs = {}
                username_field = None
                for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                    input_name = input_tag.get('name')
                    input_type = input_tag.get('type', 'text')
                    input_value = input_tag.get('value', '')
                    if input_name:
                        inputs[input_name] = input_value
                        if input_type == 'text' or ('email' in input_type and 'email' not in input_name.lower()):
                            if not username_field and 'password' not in input_name.lower():
                                username_field = input_name
                if password_input.get('name') and username_field:
                    login_form = {
                        'action': form_action,
                        'method': form_method,
                        'username_field': username_field,
                        'password_field': password_input.get('name'),
                        'other_inputs': {k: v for k, v in inputs.items() if k != username_field and k != password_input.get('name')}
                    }
                break # Found the first password form

        if not login_form:
            print(f"{Fore.YELLOW}        [WARNING] No suitable login form found on {login_url}. Skipping authenticated session analysis.{Style.RESET_ALL}")
            return []

        authenticated_sessions = []
        for i in range(num_attempts):
            print(f"        [*] Attempt {i+1}/{num_attempts} (Authenticated - Login)...", end='\r')
            
            payload = login_form['other_inputs'].copy()
            payload[login_form['username_field']] = username
            payload[login_form['password_field']] = password
            
            response = make_request(login_form['action'], method=login_form['method'], data=payload, timeout=10, allow_redirects=False)
            
            if response and (response.status_code in [200, 301, 302] and 'location' in response.headers and ("dashboard" in response.headers['location'].lower() or "admin" in response.headers['location'].lower())):
                # Successfully logged in, now get session ID
                session_id = extract_session_id(response.cookies)
                if session_id:
                    authenticated_sessions.append({'type': 'Authenticated', 'attempt': i+1, 'session_id': session_id})
                    print(f"{Fore.GREEN}        [*] Attempt {i+1} (Authenticated): Session ID: {session_id}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}        [-] Attempt {i+1} (Authenticated): Login successful but no common session cookie found.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}        [-] Attempt {i+1} (Authenticated): Login failed or unexpected response.{Style.RESET_ALL}")
            
            time.sleep(delay_per_attempt)

        # Compare authenticated session IDs
        if authenticated_sessions:
            print(f"\n{Fore.BLUE}    [+] Comparing Authenticated Session IDs:{Style.RESET_ALL}")
            first_auth_id = authenticated_sessions[0]['session_id'] if authenticated_sessions[0]['session_id'] else "N/A"
            all_same_auth = all(s['session_id'] == first_auth_id for s in authenticated_sessions if s['type'] == 'Authenticated' and s['session_id'])
            if all_same_auth:
                print(f"{Fore.RED}        [VULNERABLE] All authenticated Session IDs are identical for repeated logins. This is a critical security flaw (no session regeneration on login).{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}        Authenticated Session IDs are different for repeated logins (good).{Style.RESET_ALL}")
            
            print(f"{Fore.BLUE}    [+] Basic Analysis of a sample Authenticated Session ID ({first_auth_id}):{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}        {analyze_session_id(first_auth_id)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}    No authenticated session IDs were found to analyze.{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.YELLOW}    Skipping Authenticated Session ID analysis (no login URL or credentials provided).{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}--- Session ID Analysis Complete ---{Style.RESET_ALL}")
    print(f"{Fore.RED}Remember: This tool is for educational purposes only. Unauthorized scanning is illegal and unethical.{Style.RESET_ALL}")
    
    # Return collected session IDs for further manual analysis if needed
    return extracted_sessions

if __name__ == "__main__":
    print_banner()

    parser = argparse.ArgumentParser(description="Session ID Analyzer - For Website Authentication and Session Management Testing.")
    parser.add_argument("target_url", help="The primary URL to test (e.g., http://example.com/index.php).")
    parser.add_argument("-l", "--login_url", help="Optional: The URL of the login page (e.g., http://example.com/login.php) to test authenticated sessions.")
    parser.add_argument("-u", "--username", help="Required if --login_url is used: A valid username for authenticated session testing.")
    parser.add_argument("-p", "--password", help="Required if --login_url is used: A valid password for authenticated session testing.")
    parser.add_argument("-n", "--num_attempts", type=int, default=5,
                        help="Number of times to request the URL/login for session ID comparison (default: 5).")
    parser.add_argument("-d", "--delay", type=float, default=1,
                        help="Delay in seconds between each request/login attempt (default: 1 second).")

    args = parser.parse_args()

    # Basic URL validation
    parsed_target_url = urlparse(args.target_url)
    if not parsed_target_url.scheme or not parsed_target_url.netloc:
        print(f"{Fore.RED}Error: Invalid target URL. Please provide a full URL (e.g., http://example.com/index.php).{Style.RESET_ALL}")
        sys.exit(1)
    
    if args.login_url and (not args.username or not args.password):
        print(f"{Fore.RED}Error: If --login_url is provided, --username and --password are also required.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Final confirmation before launching the scan
    print(f"\n{Fore.YELLOW}!!! WARNING: You are about to launch a Session ID Analysis scan on {args.target_url} !!!{Style.RESET_ALL}")
    if args.login_url:
        print(f"{Fore.YELLOW}This includes testing authenticated sessions via login to {args.login_url} with provided credentials.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Ensure the provided username and password are for a TEST/VALID account and are correct.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Proceed with extreme caution. This can impact server load and potentially lock accounts.{Style.RESET_ALL}")
    confirmation = input(f"{Fore.YELLOW}Type 'YES' to confirm you understand the risks and have proper authorization: {Style.RESET_ALL}")

    if confirmation.upper() == 'YES':
        session_id_analyzer(args.target_url, args.login_url, args.username, args.password, args.num_attempts, args.delay)
    else:
        print(f"{Fore.RED}Scan aborted. Please confirm by typing 'YES' if you wish to proceed.{Style.RESET_ALL}")
        sys.exit(0)
