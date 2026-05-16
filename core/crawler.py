import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore

class WebCrawler:
    def __init__(self, start_url, max_depth=2):
        self.start_url = start_url
        self.max_depth = max_depth
        self.domain = urlparse(start_url).netloc
        self.visited = set()
        self.to_visit = [(start_url, 0)]
        self.results = {
            "endpoints": [],
            "js_files": [],
            "forms": [],
            "parameters": []
        }
        
    def fetch_page(self, url):
        try:
            headers = {"User-Agent": "VulnFinder60-Crawler/1.0"}
            response = requests.get(url, headers=headers, timeout=5)
            # Only process HTML
            if 'text/html' in response.headers.get('Content-Type', ''):
                return response.text
            return None
        except Exception:
            return None

    def parse_page(self, html, current_url):
        soup = BeautifulSoup(html, 'html.parser')
        
        # Find links
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(current_url, href)
            
            # Extract parameters
            parsed_url = urlparse(full_url)
            if parsed_url.query:
                param_keys = [p.split('=')[0] for p in parsed_url.query.split('&')]
                for p in param_keys:
                    if p and p not in self.results["parameters"]:
                        self.results["parameters"].append(p)
            
            # Same domain constraint
            if parsed_url.netloc == self.domain:
                if full_url not in self.visited and full_url not in [u[0] for u in self.to_visit]:
                    self.results["endpoints"].append(full_url)
                    return full_url
        
        # Find JS files
        for script in soup.find_all('script', src=True):
            js_url = urljoin(current_url, script['src'])
            if js_url not in self.results["js_files"]:
                self.results["js_files"].append(js_url)
                
        # Find forms
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(current_url, action)
            inputs = [inp.get('name') for inp in form.find_all('input') if inp.get('name')]
            form_data = {"url": form_url, "method": method, "inputs": inputs}
            if form_data not in self.results["forms"]:
                self.results["forms"].append(form_data)
                
        return None

    def run(self):
        print(f"{Fore.YELLOW} [*] Crawling started on {self.start_url}...{Fore.RESET}")
        
        while self.to_visit:
            current_url, depth = self.to_visit.pop(0)
            
            if current_url in self.visited or depth > self.max_depth:
                continue
                
            self.visited.add(current_url)
            html = self.fetch_page(current_url)
            
            if html:
                new_url = self.parse_page(html, current_url)
                if new_url and depth < self.max_depth:
                    self.to_visit.append((new_url, depth + 1))
                    
            # Basic limit to prevent infinite run during tests
            if len(self.visited) > 50:
                print(f"{Fore.YELLOW} [!] Reached crawler safety limit (50 pages).{Fore.RESET}")
                break
                
        print(f"{Fore.YELLOW} [*] Discovered {len(self.results['endpoints'])} endpoints, {len(self.results['js_files'])} JS files.{Fore.RESET}")
        return self.results
