import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Initialize Colorama to make it work on different terminals
init(autoreset=True)

# Define the target URL for scraping
TARGET_URL = "https://www.xvideos.com/"

def display_banner(text):
    """
    Displays a colorful banner for the script name.
    """
    banner_color = Fore.CYAN + Style.BRIGHT
    print(banner_color + "========================================")
    print(banner_color + text)
    print(banner_color + "========================================")

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
        response = requests.get(url)
        # Check if the request was successful
        response.raise_for_status()
        
        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all 'a' (link) tags
        links = soup.find_all('a', href=True)
        
        # Extract and return the specified number of links
        scraped_links = [link['href'] for link in links[:count]]
        return scraped_links
        
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error connecting to the website: {e}")
        return []

def main():
    """
    Main function to run the script.
    """
    # Display the script banner
    banner_text = """
    
█▀▄▀█ █▄▀ █░█ █▀█ █▄▄ ▀█▀ █▀█ █▀█ █░░
█░▀░█ █░█ █▀█ █▀▄ █▄█ ░█░ █▄█ █▄█ █▄▄V1.0
programed by dmnhacker"""
    display_banner(banner_text)
    
    try:
        # Get the number of links from the user
        num_links = int(input(f"{Fore.YELLOW}Enter the number of links you want: "))
        
        print(f"\n{Fore.GREEN}Fetching {num_links} links from {TARGET_URL}...")
        
        # Fetch the links
        links = get_links(TARGET_URL, num_links)
        
        if not links:
            print(f"{Fore.RED}No links found.")
            return

        # Print the links with colors
        print(f"{Fore.MAGENTA}\nFound links:")
        for i, link in enumerate(links, 1):
            # Alternate colors for better readability
            color = Fore.BLUE if i % 2 != 0 else Fore.CYAN
            print(f"{color}{i}. {link}")
            
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a number.")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}")

if __name__ == "__main__":
    main()
