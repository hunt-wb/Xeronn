#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import re
import sys
import time
from typing import TextIO, Optional # Import for type hinting the file handle

# --- ANSI COLOR CODES ---
HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'

# Define the categories and their extraction patterns
EXTRACTION_PATTERNS = {
    1: {"name": "Email Addresses", "regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"},
    2: {"name": "Phone Numbers (Simple)", "regex": r"(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}"},
    3: {"name": "URLs/Links (href)", "regex": r""}
}

# --- Helper function to print/save consistently ---
def output(message: str, file_handle: Optional[TextIO] = None, color: bool = True):
    """Prints a message to the console and optionally saves it to a file."""
    # Write to console with color
    if color:
        sys.stdout.write(message)
    else:
        # Write to file without ANSI color codes
        no_color_message = re.sub(r'\033\[[0-9;]*m', '', message)
        if file_handle:
            file_handle.write(no_color_message)
            
    sys.stdout.flush()

# --- IMPROVED ANIMATION/LOADING FUNCTION ---
def loading_animation(task_description: str, duration: int = 2):
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
    
    # Clear the animation line and replace with a success message
    sys.stdout.write(f"\r{' ' * 50}\r") # Clear line
    sys.stdout.write(f"{OKGREEN}✓ {task_description} COMPLETE.{ENDC}\n")
    sys.stdout.flush()


def fetch_html(url: str, file_handle: Optional[TextIO] = None) -> str:
    """Fetches HTML content with visual feedback."""
    try:
        loading_animation(f"Connecting to {url}", 1) 
        
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; Xeron/1.0)'}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status() 
        
        message = f"{OKGREEN}   [STATUS] HTML captured successfully!{ENDC} ({len(response.content)} bytes)\n"
        output(message, file_handle)
        return response.text
    except requests.exceptions.RequestException as e:
        message = f"\n{FAIL}{BOLD}   [ERROR] Connection failed or bad status code.{ENDC} Details: {e}\n"
        output(message, file_handle, color=True) # Always show error in console
        return ""

def extract_links(html_content: str) -> list[str]:
    """Uses BeautifulSoup to find all links."""
    loading_animation("Parsing HTML structure", 1) 
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        links = []
        for tag in soup.find_all('a', href=True):
            links.append(tag['href'])
        return links
    except Exception as e:
        message = f"\n{FAIL}   [ERROR] Parsing failed: {e}{ENDC}\n"
        output(message, color=True) 
        return []

def extract_data(html_content: str, choices: list[int]) -> dict[int, set[str]]:
    """Extracts data based on selected categories."""
    results = {}
    
    # 1. Regex Extraction
    for key in choices:
        if key in EXTRACTION_PATTERNS and key != 3: 
            pattern = EXTRACTION_PATTERNS[key]["regex"]
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            results[key] = set(matches) 
    
    # 2. BeautifulSoup (Links) Extraction
    if 3 in choices:
        results[3] = set(extract_links(html_content))
        
    return results

def print_results(results: dict[int, set[str]], choices: list[int], file_handle: Optional[TextIO] = None):
    """Prints the extracted results clearly and colorfully, saving to file."""
    output(f"\n{HEADER}--- E X T R A C T I O N   R E P O R T ---\n{ENDC}", file_handle, color=True)
    
    for choice in choices:
        if choice in results:
            name = EXTRACTION_PATTERNS[choice]["name"]
            data = results[choice]
            
            if data:
                message = f"\n{OKGREEN}{BOLD}>>> {name}{ENDC} ({len(data)} unique items found):\n"
                output(message, file_handle, color=True)
                
                # Use a specific color for the data points
                for item in sorted(list(data)):
                    output(f"{OKBLUE}  - {item}{ENDC}\n", file_handle, color=True)
            else:
                message = f"\n{WARNING}>>> No {name} found.{ENDC}\n"
                output(message, file_handle, color=True)

def print_categories():
    """Prints the categories available to the user with a clean list."""
    print(f"\n{HEADER}{BOLD}--- D A T A   E X T R A C T I O N   M O D E S ---{ENDC}")
    for key, val in EXTRACTION_PATTERts.items():
        print(f"{WARNING}{key}. {val['name']}{ENDC}")
    print(f"{WARNING}0. Extract All (1, 2, and 3){ENDC}")
    sys.stdout.write(f"{OKBLUE}Enter category numbers (e.g., 1 3): {ENDC}")
    sys.stdout.flush()


def main():
    # --- FILE OUTPUT SETUP ---
    OUTPUT_FILENAME = "roxen.txt"
    file_handle: Optional[TextIO] = None
    
    try:
        # Open the file for writing (creates it or overwrites it)
        file_handle = open(OUTPUT_FILENAME, 'w', encoding='utf-8')

        output(f"{HEADER}{BOLD}\n+------------------------------------+\n{ENDC}", file_handle)
        output(f"{HEADER}{BOLD}| {OKGREEN}X E R O N   W E B   S C R A P E R{ENDC} {HEADER}{BOLD}|\n{ENDC}", file_handle)
        output(f"{HEADER}{BOLD}+------------------------------------+\n{ENDC}", file_handle)
        output(f"{OKGREEN}Results will be saved to: {OUTPUT_FILENAME}{ENDC}\n", file_handle)
        
        # 1. Ask for URL
        sys.stdout.write(f"{OKBLUE}URL: {ENDC}")
        sys.stdout.flush()
        url_input = sys.stdin.readline().strip()

        if not url_input:
            output(f"{FAIL}URL cannot be empty. Exiting.{ENDC}\n", file_handle, color=True)
            return
        
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'http://' + url_input

        # 2. Capture HTML
        loading_animation("Starting web connection", 1)
        html_content = fetch_html(url_input, file_handle)
        
        if not html_content:
            return

        # 3. Ask for Keywords/Categories
        print_categories()
        
        choices_input = sys.stdin.readline().strip()
        choices = []
        
        if '0' in choices_input.split():
            choices = [1, 2, 3]
        else:
            for part in choices_input.split():
                try:
                    choice = int(part)
                    if choice in EXTRACTION_PATTERNS:
                        choices.append(choice)
                except ValueError:
                    continue
        
        if not choices:
            output(f"{WARNING}No valid categories selected. Exiting.{ENDC}\n", file_handle, color=True)
            return

        # 4. Extract and Print
        loading_animation("Running data extraction routines", 1)
        results = extract_data(html_content, choices)
        print_results(results, choices, file_handle)

    except EOFError:
        output(f"\n{FAIL}Input interrupted. Exiting.{ENDC}\n", file_handle, color=True)
    except Exception as e:
        output(f"\n{FAIL}An unexpected error occurred: {e}{ENDC}\n", file_handle, color=True)
    finally:
        # Close the file handle to ensure data is written
        if file_handle:
            file_handle.close()
            output(f"\n{OKGREEN}Results successfully saved to {OUTPUT_FILENAME}.{ENDC}\n")

if __name__ == "__main__":
    main()
