import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from urllib.parse import urlparse, urljoin # برای تحلیل و ترکیب URLها

# Initialize Colorama to make it work on different terminals
init(autoreset=True)

# لیست دامنه‌های مجاز برای استخراج لینک
# این لیست از دامنه‌هایی که شما ارائه دادید ایجاد شده است.
ALLOWED_DOMAINS = {
    "ucoz.com", "17ebook.co", "sapo.pt", "aladel.net", "bpwhamburgorchardpark.org",
    "clicnews.com", "amazonaws.com", "dfwdiesel.net", "divineenterprises.net",
    "fantasticfilms.ru", "blogspot.de", "gardensrestaurantandcatering.com",
    "ginedis.com", "gncr.org", "hdvideoforums.org", "hihanin.com",
    "kingfamilyphotoalbum.com", "4shared.com", "likaraoke.com", "mactep.org",
    "magic4you.nu", "sendspace.com", "marbling.pe.kr", "nacjalneg.info",
    "pronline.ru", "purplehoodie.com", "qsng.cn", "comcast.net",
    "seksburada.net", "sportsmansclub.net", "stock888.cn", "fc2.com",
    "tathli.com", "teamclouds.com", "texaswhitetailfever.com", "hotfile.com",
    "wadefamilytree.org", "xnescat.info", "mail.ru", "yt118.com", "17ebook.com"
}

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
    Fetches a specified number of links from the given URL,
    filtering them by a predefined list of allowed domains.
    
    Args:
        url (str): The URL to scrape.
        count (int): The number of links to retrieve.
    
    Returns:
        list: A list of scraped links that belong to allowed domains.
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
        links_found = soup.find_all('a', href=True)
        
        scraped_links = []
        for link_tag in links_found:
            href = link_tag['href']
            
            # تبدیل URLهای نسبی به مطلق (مثلاً "/about" به "http://example.com/about")
            absolute_href = urljoin(url, href)
            parsed_href = urlparse(absolute_href)
            
            # استخراج دامنه (netloc) از URL و نرمال‌سازی آن (حذف 'www.')
            link_domain = parsed_href.netloc.lower()
            if link_domain.startswith('www.'):
                link_domain = link_domain[4:] 
            
            # فیلتر کردن لینک‌های خالی، لینک‌های داخلی (#) و لینک‌هایی که در دامنه‌های مجاز نیستند
            if absolute_href and not absolute_href.startswith('#') and link_domain in ALLOWED_DOMAINS:
                scraped_links.append(absolute_href)
                if len(scraped_links) >= count:
                    break # به محض رسیدن به تعداد لینک‌های درخواستی، حلقه متوقف می‌شود
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
    
█▀▄▀█ █▄▀ █░█ █▀█ █▄▄ ▀█▀ █▀█ █▀█ █░░
█░▀░█ █░█ █▀█ █▀▄ █▄█ ░█░ █▄█ █▄█ █▄▄V1.0
programed by dmnhacker"""
    display_banner(banner_text)
    
    try:
        # Get the target URL from the user
        target_url_input = input(f"{Fore.YELLOW}Enter the target website address (e.g., https://example.com): {Style.RESET_ALL}")
        
        # Get the number of links from the user
        num_links = int(input(f"{Fore.YELLOW}Enter the number of links you want: {Style.RESET_ALL}"))
        
        print(f"\n{Fore.GREEN}Fetching {num_links} links from {target_url_input} with domain filter...")
        
        # Fetch the links
        links = get_links(target_url_input, num_links)
        
        if not links:
            print(f"{Fore.RED}No links found from allowed domains or an error occurred during fetching.")
            return

        # Print the links with colors
        print(f"{Fore.MAGENTA}\nFound links (filtered by allowed domains):")
        for i, link in enumerate(links, 1):
            # Alternate colors for better readability
            color = Fore.BLUE if i % 2 != 0 else Fore.CYAN
            print(f"{color}{i}. {link}{Style.RESET_ALL}")
            
    except ValueError:
        print(f"{Fore.RED}Invalid input. Please enter a valid number for links.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
