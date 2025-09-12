# -*- coding: utf-8 -*-
import sys
import os
import hashlib
import time
import socket
import requests
from bs4 import BeautifulSoup
from datetime import datetime

def clear_screen():
    """Clears the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Prints a professional-looking banner."""
    clear_screen()
    print("---------------------------------------------")
    print("                plane B V1.0                 ")
    print("---------------------------------------------")
    print()

def get_menu_choice():
    """Displays the menu and gets the user's choice."""
    print("Please select a tool to use:")
    print("1. Port Scanner")
    print("2. Password Hasher")
    print("3. File Integrity Monitor")
    print("4. Web Crawler")
    print("5. Basic SQL Injection Scanner")
    print("6. Subdomain Enumerator")
    print("7. Password Dictionary Creator")
    print("8. Exit")
    print("-" * 30)
    
    try:
        choice = int(input("Enter your choice: "))
        return choice
    except ValueError:
        print("Error! Please enter a valid number.")
        time.sleep(2)
        return -1

# --- TOOL 1: PORT SCANNER ---
def port_scanner():
    """A basic port scanner to check for open ports."""
    print_banner()
    print("--- Port Scanner ---")
    target = input("Enter target IP address or hostname: ")
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Error! Hostname could not be resolved.")
        time.sleep(2)
        return

    print("-" * 30)
    print(f"Scanning {target_ip}...")

    # Common ports to scan
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389, 8080]
    open_ports = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        
        result = sock.connect_ex((target_ip, port))
        
        if result == 0:
            print(f"Port {port} is OPEN.")
            open_ports.append(port)
        sock.close()

    print("-" * 30)
    if open_ports:
        print(f"Open ports found: {', '.join(map(str, open_ports))}")
    else:
        print("No open ports found from the common list.")
    input("\nPress Enter to return to the menu...")

# --- TOOL 2: PASSWORD HASHER ---
def password_hasher():
    """Hashes a password to understand hashing concepts."""
    print_banner()
    print("--- Password Hasher ---")
    password = input("Enter password to hash: ")
    
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    md5_hash = hashlib.md5(password.encode()).hexdigest()

    print("-" * 30)
    print(f"Original Password: {password}")
    print(f"SHA-256 Hash:      {sha256_hash}")
    print(f"MD5 Hash:          {md5_hash}")
    print("\nNote: MD5 is considered insecure for password hashing.")
    input("\nPress Enter to return to the menu...")

# --- TOOL 3: FILE INTEGRITY MONITOR ---
def file_monitor():
    """Monitors a directory for file changes."""
    print_banner()
    print("--- File Integrity Monitor ---")
    directory_to_monitor = input("Enter the directory path to monitor (e.g., C:\\Users\\user\\Desktop): ")

    if not os.path.isdir(directory_to_monitor):
        print("Error! The path provided is not a valid directory.")
        time.sleep(2)
        return

    print("-" * 30)
    print(f"Monitoring directory: {directory_to_monitor}...")
    print("Press Ctrl+C to stop.")
    
    # Get initial file states (filename and modification time)
    before = {f: os.path.getmtime(os.path.join(directory_to_monitor, f)) 
              for f in os.listdir(directory_to_monitor)}
    
    try:
        while True:
            time.sleep(2) # Check every 2 seconds
            after = {f: os.path.getmtime(os.path.join(directory_to_monitor, f))
                     for f in os.listdir(directory_to_monitor)}
            
            added_files = [f for f in after if f not in before]
            removed_files = [f for f in before if f not in after]
            modified_files = [f for f in before if f in after and before[f] != after[f]]

            if added_files:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] New file(s) added: {', '.join(added_files)}")
            if removed_files:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] File(s) removed: {', '.join(removed_files)}")
            if modified_files:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] File(s) modified: {', '.join(modified_files)}")
            
            before = after
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
        input("Press Enter to return to the menu...")

# --- TOOL 4: WEB CRAWLER ---
def web_crawler():
    """A simple web crawler to find links on a page."""
    print_banner()
    print("--- Web Crawler ---")
    url = input("Enter the full URL of the website (e.g., https://www.google.com): ")
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        links = []
        for a_tag in soup.find_all('a', href=True):
            link = a_tag['href']
            # Only display full links for simplicity
            if link.startswith('http'):
                links.append(link)
        
        if links:
            print("-" * 30)
            print(f"Links found on {url}:")
            for link in sorted(list(set(links))):
                print(f"  - {link}")
        else:
            print("No links found on this page.")

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to website: {e}")
    
    input("\nPress Enter to return to the menu...")

# --- TOOL 5: BASIC SQL INJECTION SCANNER ---
def sql_injection_scanner():
    """A basic scanner to detect SQL Injection vulnerabilities."""
    print_banner()
    print("--- Basic SQL Injection Scanner ---")
    url = input("Enter the URL to test (e.g., http://testsite.com/products.php?id=1): ")
    
    payloads = [
        "'", "')", "';",
        "' OR '1'='1",
        "' OR '1'='1'--",
        '" OR "1"="1'
    ]
    
    found_vulnerability = False
    
    for payload in payloads:
        test_url = f"{url}{payload}"
        print(f"Testing payload: {payload} ...")
        
        try:
            response = requests.get(test_url, timeout=5)
            # Check for common SQL error messages in the response
            if any(error in response.text for error in ["syntax error", "mysql_fetch_array()", "odbc message", "supplied argument is not a valid MySQL result"]):
                print(f"\nPotential SQLi vulnerability found with payload: {payload}")
                found_vulnerability = True
                break
        except requests.exceptions.RequestException as e:
            print(f"Connection error: {e}")
            
    if not found_vulnerability:
        print("\nNo common SQLi vulnerabilities detected.")
    
    input("\nPress Enter to return to the menu...")

# --- TOOL 6: SUBDOMAIN ENUMERATOR ---
def subdomain_scanner():
    """A simple tool to enumerate common subdomains for a domain."""
    print_banner()
    print("--- Subdomain Enumerator ---")
    domain = input("Enter the root domain (e.g., google.com): ")
    
    # Small, pre-defined wordlist
    subdomains = ['www', 'mail', 'ftp', 'blog', 'api', 'dev', 'test', 'admin', 'portal', 'status']
    found_subdomains = []
    
    print("-" * 30)
    print(f"Searching for subdomains of {domain}...")
    
    for subdomain in subdomains:
        url = f"http://{subdomain}.{domain}"
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                print(f"Found: {url}")
                found_subdomains.append(url)
        except requests.exceptions.RequestException:
            continue
            
    print("-" * 30)
    if found_subdomains:
        print(f"Found {len(found_subdomains)} active subdomains.")
    else:
        print("No active subdomains found from the wordlist.")
        
    input("\nPress Enter to return to the menu...")

# --- TOOL 7: PASSWORD DICTIONARY CREATOR ---
def password_dictionary_creator():
    """Generates a password dictionary based on user-provided words."""
    print_banner()
    print("--- Password Dictionary Creator ---")
    print("Enter a few keywords to generate a custom wordlist (e.g., name, pet's name, birth year).")
    
    keywords = input("Enter words separated by commas (e.g., John,1990,Max): ").split(',')
    keywords = [k.strip() for k in keywords if k.strip()]
    
    output_filename = input("Enter output filename (e.g., my_dictionary.txt): ")
    
    if not keywords:
        print("No keywords provided. Exiting.")
        time.sleep(2)
        return
        
    generated_passwords = set()
    
    # Basic permutations
    for word in keywords:
        generated_passwords.add(word)
        generated_passwords.add(word.lower())
        generated_passwords.add(word.upper())
        generated_passwords.add(word.capitalize())
        
        # Add simple number combinations
        for num in range(10):
            generated_passwords.add(f"{word}{num}")
            generated_passwords.add(f"{word}{num}{num}")
            
        # Add simple special characters
        for char in ['!', '@', '#', '$']:
            generated_passwords.add(f"{word}{char}")
            
    try:
        with open(output_filename, 'w') as f:
            for password in sorted(list(generated_passwords)):
                f.write(f"{password}\n")
        
        print(f"\nSuccessfully generated {len(generated_passwords)} passwords in '{output_filename}'.")
        
    except IOError as e:
        print(f"Error writing to file: {e}")
    
    input("\nPress Enter to return to the menu...")
    
def main():
    """Main function to run the toolkit."""
    while True:
        print_banner()
        choice = get_menu_choice()
        
        if choice == 1:
            port_scanner()
        elif choice == 2:
            password_hasher()
        elif choice == 3:
            file_monitor()
        elif choice == 4:
            web_crawler()
        elif choice == 5:
            sql_injection_scanner()
        elif choice == 6:
            subdomain_scanner()
        elif choice == 7:
            password_dictionary_creator()
        elif choice == 8:
            print("Goodbye! Stay ethical and secure.")
            sys.exit(0)
        else:
            print("Invalid option. Please try again.")
            time.sleep(2)

if __name__ == "__main__":
    # Check and install required libraries
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        print("Required libraries (requests and beautifulsoup4) are not installed.")
        print("Please run the following command in your terminal:")
        print("pip install requests beautifulsoup4")
        sys.exit(1)
    
    main()
