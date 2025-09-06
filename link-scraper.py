import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Initialize Colorama to make it work on different terminals
init(autoreset=True)


def get_links(url, count):
    """
    Fetches a specified number of links from the given URL.
    
    Args:
        url (str): The URL to scrape.
        count (int): The number of links to retrieve.
    
    Returns:
        list: A list of scraped links.
    """
    try:
        # Send a GET request to the URL
        # اضافه کردن یک User-Agent برای شبیه‌سازی مرورگر و جلوگیری از بلاک شدن توسط برخی سایت‌ها
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=10) # اضافه کردن timeout
        # Check if the request was successful
        response.raise_for_status() # برای تشخیص خطاهای HTTP مانند 404 یا 500
        
        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all 'a' (link) tags
        links = soup.find_all('a', href=True)
        
        # Extract and return the specified number of links
        scraped_links = []
        for link in links:
            href = link['href']
            # فیلتر کردن لینک‌های خالی و لینک‌های داخلی که فقط # هستند
            if href and not href.startswith('#'):
                scraped_links.append(href)
            if len(scraped_links) >= count:
                break
        return scraped_links
        
    except requests.exceptions.MissingSchema:
        print(f"{Fore.RED}Error: Invalid URL. Make sure it starts with http:// or https://")
        return []
    except requests.exceptions.ConnectionError as e:
        print(f"{Fore.RED}Error: Could not connect to the website. Please check the URL and your internet connection. Details: {e}")
        return []
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}Error: The request timed out after 10 seconds. The server might be slow or unreachable.")
        return []
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}An unexpected request error occurred: {e}")
        return []
    except Exception as e:
        print(f"{Fore.RED}An error occurred during scraping: {e}")
        return []

def main():
    """
    Main function to run the script.
    """
    # Display the script banner
    banner_text = """
    
    █░░ █ █▄░█ █▄▀   █▀ █▀▀ █▀█ ▄▀█ █▀█ █▀▀ █▀█
    █▄▄ █ █░▀█ █░█   ▄█ █▄▄ █▀▄ █▀█ █▀▀ ██▄ █▀▄
            Link Scraper V1.1
"""
    display_banner(banner_text)
    
    try:
        # Get the target URL from the user
        target_url_input = input(f"{Fore.YELLOW}Enter the target website address (e.g., https://example.com): {Style.RESET_ALL}")
        
        # Get the number of links from the user
        num_links = int(input(f"{Fore.YELLOW}Enter the number of links you want: {Style.RESET_ALL}"))
        
        print(f"\n{Fore.GREEN}Fetching {num_links} links from {target_url_input}...")
        
        # Fetch the links
        links = get_links(target_url_input, num_links)
        
        if not links:
            print(f"{Fore.RED}No links found or an error occurred during fetching.")
            return

        # Print the links with colors
        print(f"{Fore.MAGENTA}\nFound links:")
        for i, link in enumerate(links, 1):
            # Alternate colors for better readability
            color = Fore.BLUE if i % 2 != 0 else Fore.CYAN
            # The following line was updated to remove the numbering
            print(f"{color}{link}{Style.RESET_ALL}")
            
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a valid number for links.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred: {e}{Style.RESET_ALL}")

if __name__ == "__main__":    main()
