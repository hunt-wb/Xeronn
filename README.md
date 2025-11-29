# 🕸️ Xeron Web Scraper

Xeron is a simple, command-line web scraping tool built in Python for fetching HTML content from a given URL and extracting specific data patterns in a clean, user-friendly interface.

The eresults are saved to a file named `roxen.txt`.

---

## ✨ Features

* **HTML Fetching:** Uses the `requests` library to reliably connect to and retrieve page content.
* **Targeted Extraction:** Uses powerful **Regular Expressions** and **BeautifulSoup** to accurately identify and extract data.
* **Interactive Interface:** Provides clear, colored prompts and visual loading animations for a smooth user experience.
* **Output Management:** Saves all final results to `roxen.txt` for easy review and processing.

---

## 🛠️ Prerequisites

Before running Xeron, you must have **Python 3** and the necessary libraries installed on yoursystem.

### Termux Installation Command

Run the following consolidated command in your Termux terminal to install Python, `requests`, and `beautifulsoup4`:

```bash
pkg install python -y && pip install requests beautifulsoup4
