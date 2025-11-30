#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import re
import sys
import time
from typing import TextIO, Optional, Set, Dict
from urllib.parse import urljoin, urlparse

# --- ANSI COLOR CODES ---
HEADER = '\033\s*[^\n<]+"},
    
    # 2. Email: Standard email address pattern
    2: {"name": "Email Addresses", "regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"},
    
    # 3. Username: Common fields near input tags
    3: {"name": "Usernames/IDs", "regex": r"(?:user|username|login|id)\s*[:=]\s*['\"]?([A-Za-z0-9._-]+)['\"]?"},
    
    # 4. Admin: Common words pointing to admin pages or directories
    4: {"name": "Admin Keywords", "regex": r"(?:admin|administrator|control\s*panel|dashboard|phpmyadmin)\s*[:=/\s*][A-Za-z0-9\._-]{2,}"},
    
    # 5. Password: Common passwords/keys found in configurations
    5: {"name": "Passwords/Keys", "regex": r"(?:pass|password|pwd|secret|key|token|api_key|db_pass)\s*[:=]\s*['\"]?([A-Za-z0-9!@#$%^&*_+-]{4,})['\"]?"},
    
    # 6. URL: Links (handled by BeautifulSoup)
    6: {"name": "URLs/Links (href)", "regex": r""},
    
    # 7. NEW: Online Identifiers (IP addresses, UUIDs, etc.)
    7: {"name": "Online Identifiers (IPs/GUIDs)", "regex": r"\b(?:(?:\d{1,3}\.){3}\d{1,3})|([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})\b"},
    
    # 8. NEW: Sensitive PII (Names, Address keywords, Phone formats)
    8: {"name": "Sensitive PII/Financial", "regex": r"(?:name|address|phone|ssn|social\s*security|license|passport|card|bank)\s*[:=]\s*['\"]?([A-Za-z0-9\s#\.\(\)-]+)['\"]?"},
}
NUM_CATEGORIES = len(EXTRACTION_PATTERNS)
MAX_PAGES_TO_CRAWL = 50  # Safety limit for recursive crawling
SENSITIVE_FILES = [      # Files to search for directly on the domain root or common dirs
    '/.env', '/config.php', '/wp-config.php', '/database.yml', '/web.config',
    '/admin/config.php', '/backup.sql', '/data.db', '/config/.env',
]

# --- GLOBAL TRACKERS ---
crawled_urls: Set[str] = set()
pages_to_crawl: Set[str] = set()
session_cookies: Dict[str, str] = {}
total_extracted_data: dict[int, set[str]] = {k: set() for k in EXTRACTION_PATTERNS.keys()}

# --- CORE FUNCTIONS ---

def output(message: str, file_handle: Optional = None, color: bool = True):
    """Prints a message to the console and optionally saves it to a file, stripping color."""
    if color:
        sys.stdout.write(message)
    else:
        no_color_message = re.sub(r'\033\[[0-9;]*m', '', message)
        if file_handle:
            file_handle.write(no_color_message)
            
    sys.stdout.flush()

def loading_animation(task_description: str, duration: float = 1.0):
    """Shows a simple, non-logging animation during a task."""
    symbols = ['|', '/', '-', '\\']
    start_time = time.time()
    sys.stdout.write(f"{WARNING}{task_description}... {ENDC}")
    sys.stdout.flush()

    while time.time() - start_time < duration:
        for symbol in symbols:
            sys.stdout.write(f"\r{WARNING}{task_description}... [{symbol}]{ENDC}")
            sys.stdout.flush()
            time.sleep(0.1)
    
    sys.stdout.write(f"\r{' ' * 50}\r")
    sys.stdout.write(f"{OKGREEN}✓ {task_description} COMPLETE.{ENDC}\n")
    sys.stdout.flush()

def is_valid_url_format(url: str) -> bool:
    """Checks if the input string is a valid URL format."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def fetch_html(url: str, file_handle: Optional = None) -> str:
    """Fetches HTML content, utilizing global session cookies if available."""
    global session_cookies
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; Xeron/1.0)'}
        
        response = requests.get(url, headers=headers, cookies=session_cookies, timeout=10)
        response.raise_for_status() 
        
        if response.cookies:
            session_cookies.update(response.cookies.items())
        
        message = f"{OKGREEN}   Fetched {url} ({len(response.content)} bytes){ENDC}\n"
        output(message, file_handle)
        return response.text
    except requests.exceptions.RequestException as e:
        message = f"{FAIL}   Failed to fetch {url}. Details: {e}{ENDC}\n"
        output(message, file_handle, color=True)
        return ""

def extract_and_enqueue(html_content: str, base_url: str, file_handle: Optional = None):
    """Parses HTML, extracts links and link text, and adds new links to the crawl queue."""
    global pages_to_crawl
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # 1. Extract Links and Link Text (Category 6 and 1)
        new_links_on_page: Set[str] = set()
        
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            link_text = tag.get_text().strip()
            
            # Acquisition of link text for Category 1 (Logs/Errors)
            if link_text and len(link_text) > 4 and link_text not in:
                total_extracted_data.[1]add(f"Link Text: {link_text} (from {base_url})")

            # Resolve and queue link for crawling
            absolute_url = urljoin(base_url, href)
            
            if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                if absolute_url not in crawled_urls and absolute_url not in pages_to_crawl:
                    pages_to_crawl.add(absolute_url)
                    new_links_on_page.add(absolute_url)
            
            # Save all links found to Category 6
            total_extracted_data.[2]add(absolute_url) 
            
        message = f"{WARNING}   [INFO] Discovered {len(new_links_on_page)} new internal links.{ENDC}\n"
        output(message, file_handle)

        # 2. Run Regex Extractions (Categories 1-5, 7, 8)
        for key in EXTRACTION_PATTERNS.keys():
            if key == 6: # Skip links, already handled by BeautifulSoup
                continue
            
            pattern = EXTRACTION_PATTERNS[key]["regex"]
            
            if key == 1: # Logs/Errors (Full pattern match, excluding link text already added)
                 matches = re.findall(pattern, html_content, re.IGNORECASE | re.MULTILINE)
            else: # Credentials/Keywords (Capture only the group/value)
                 # Note: regex patterns for 3, 4, 5, 7, 8 use groups () to capture the value
                 matches =

            # Add unique matches to the global tracker
            for match in matches:
                total_extracted_data[key].add(match)

    except Exception as e:
        message = f"{FAIL}   Failed during parsing/regex extraction: {e}{ENDC}\n"
        output(message, file_handle, color=True)

def check_sensitive_files(base_url: str, file_handle: Optional = None):
    """Attempts to fetch sensitive configuration/database files directly."""
    output(f"\n{HEADER}--- TARGETED FILE SEARCH ---\n{ENDC}", file_handle, color=True)
    
    for file_path in SENSITIVE_FILES:
        target_url = urljoin(base_url, file_path)
        output(f"{WARNING}   Checking: {target_url}...{ENDC}\n", file_handle)
        
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; Xeron/1.0)'}
            response = requests.get(target_url, headers=headers, cookies=session_cookies, timeout=5)
            
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', 'text/plain')
                
                if 'text' in content_type or 'application/json' in content_type:
                    message = f"{OKGREEN}{BOLD}!!! DATABASE/CONFIG FILE FOUND!!!{ENDC} -> {target_url}\n"
                    output(message, file_handle, color=True)
                    
                    # Add content to 'Logs/Errors' (Category 1) for later review
                    total_extracted_data.[1]add(f"FOUND SENSITIVE FILE: {target_url}\nCONTENT START: {response.text[:500]}...")
                
                else:
                    output(f"{WARNING}   [INFO] Found file, but not readable text (Type: {content_type}).{ENDC}\n", file_handle)
            
        except requests.exceptions.RequestException:
            pass 

def crawl_website(start_url: str, file_handle: Optional = None):
    """The main recursive crawling logic."""
    global pages_to_crawl, crawled_urls
    
    pages_to_crawl.add(start_url)
    
    check_sensitive_files(start_url, file_handle)

    output(f"\n{HEADER}--- RECURSIVE CRAWL START ({MAX_PAGES_TO_CRAWL} max) ---\n{ENDC}", file_handle, color=True)
    
    while pages_to_crawl and len(crawled_urls) < MAX_PAGES_TO_CRAWL:
        current_url = pages_to_crawl.pop()
        
        if current_url in crawled_urls:
            continue
            
        crawled_urls.add(current_url)
        
        output(f"{WARNING}   Page {len(crawled_urls)}/{MAX_PAGES_TO_CRAWL}: {current_url}{ENDC}\n", file_handle)
        
        html_content = fetch_html(current_url, file_handle)
        if html_content:
            extract_and_enqueue(html_content, current_url, file_handle)

def print_results(file_handle: Optional = None):
    """Prints the final comprehensive report, including cookie information."""
    output(f"\n{HEADER}--- FINAL CRAWL REPORT ---\n{ENDC}", file_handle, color=True)
    
    target_url = list(crawled_urls) if crawled_urls else "N/A"
    
    output(f"{OKBLUE}URL Target:{ENDC} {target_url}\n", file_handle)
    output(f"{OKBLUE}Pages Crawled:{ENDC} {len(crawled_urls)}\n", file_handle)
    output(f"{OKBLUE}Total Unique Links Discovered:{ENDC} {len(total_extracted_data[2])}\n", file_handle)
    
    # --- COOKIE SECTION ---
    output(f"\n{HEADER}--- SESSION/COOKIE ACQUISITION ---\n{ENDC}", file_handle, color=True)
    if session_cookies:
        output(f"{OKGREEN}{BOLD}Acquired Cookies ({len(session_cookies)} total):{ENDC}\n", file_handle)
        for key, value in session_cookies.items():
            output(f"{OKBLUE}  - {key}: {value}{ENDC}\n", file_handle, color=True)
    else:
        output(f"{WARNING}No session cookies were acquired during the crawl.{ENDC}\n", file_handle, color=True)
    
    # --- EXTRACTION RESULTS ---
    output(f"\n{HEADER}--- DATA EXTRACTION RESULTS ---\n{ENDC}", file_handle, color=True)
    
    for key in sorted(total_extracted_data.keys()):
        name = EXTRACTION_PATTERNS[key]["name"]
        data = total_extracted_data[key]
        
        if data:
            message = f"\n{OKGREEN}{BOLD}>>> {name}{ENDC} ({len(data)} unique items found):\n"
            output(message, file_handle, color=True)
            
            for item in sorted(list(data))[:100]:
                output(f"{OKBLUE}  - {item}{ENDC}\n", file_handle, color=True)
        else:
            message = f"\n{WARNING}>>> No {name} found.{ENDC}\n"
            output(message, file_handle, color=True)


def print_categories():
    """Prints the categories available to the user with a clean list."""
    print(f"\n{HEADER}{BOLD}--- D A T A   E X T R A C T I O N   M O D E S ---{ENDC}")
    
    for key in sorted(EXTRACTION_PATTERNS.keys()):
        val = EXTRACTION_PATTERNS[key]
        print(f"{WARNING}{key}. {val['name']}{ENDC}")
        
    print(f"{WARNING}0. Extract All (1 to {NUM_CATEGORIES}){ENDC}")
    sys.stdout.write(f"{OKBLUE}Enter category numbers (e.g., 2 5 8): {ENDC}")
    sys.stdout.flush()


def main():
    global crawled_urls, pages_to_crawl, total_extracted_data, session_cookies
    file_handle: Optional = None
    url_input = "N/A"
    
    try:
        # --- UI START ---
        output(f"{HEADER}{BOLD}\n+------------------------------------+\n{ENDC}")
        output(f"{HEADER}{BOLD}| {OKGREEN}X E R O N   W E B   C R A W L E R{ENDC} {HEADER}{BOLD}|\n{ENDC}")
        output(f"{HEADER}{BOLD}+------------------------------------+\n{ENDC}")
        output(f"{OKGREEN}Results will be saved to: {OUTPUT_FILENAME}{ENDC}\n")

        # 1. Ask for URL and Validate
        sys.stdout.write(f"{OKBLUE}Target URL (e.g., https://example.com): {ENDC}")
        sys.stdout.flush()
        url_input = sys.stdin.readline().strip()

        if not url_input:
            output(f"{FAIL}URL cannot be empty. Exiting.{ENDC}\n", color=True)
            return

        if not url_input.startswith(('http://', 'https://')):
            url_input = 'http://' + url_input

        if not is_valid_url_format(url_input):
            output(f"{FAIL}{BOLD}Invalid URL format.{ENDC} Please ensure it is in the format {OKBLUE}https://example.com{ENDC}.\n", color=True)
            return
        
        # 2. Start File Output
        file_handle = open(OUTPUT_FILENAME, 'w', encoding='utf-8')
        output(f"Started analysis at: {time.ctime()}\n", file_handle, color=False)
        output(f"Target: {url_input}\n", file_handle, color=False)
        
        # 3. Core Crawl and Extraction
        loading_animation("Initializing crawler and setting up queues", 1)
        crawl_website(url_input, file_handle)
        loading_animation("Finalizing extraction report", 1)
        
        # 4. Print Final Results (Console and File)
        print_results(file_handle)
        print_results(None)
        
    except EOFError:
        output(f"\n{FAIL}Input interrupted. Exiting.{ENDC}\n", file_handle, color=True)
    except Exception as e:
        output(f"\n{FAIL}An unexpected error occurred: {e}{ENDC}\n", file_handle, color=True)
    finally:
        if file_handle:
            file_handle.close()
            output(f"\n{OKGREEN}Results successfully saved and finalized in {OUTPUT_FILENAME}.{ENDC}\n")
        
        # Ensures roxen.txt is never empty if a URL was provided
        if url_input!= "N/A":
            if file_handle is None or file_handle.tell() == 0:
                with open(OUTPUT_FILENAME, 'w', encoding='utf-8') as f:
                    f.write("XERON CRAWLER REPORT\n\n")
                    f.write(f"The crawl finished with no content. Target URL: {url_input}.\n")
                    f.write("Please check the network connection or ensure the URL is correct.")
                output(f"\n{FAIL}Warning: The crawl failed or found no data. A minimal report was saved to {OUTPUT_FILENAME}.{ENDC}\n", color=True)


if __name__ == "__main__":
    main()
