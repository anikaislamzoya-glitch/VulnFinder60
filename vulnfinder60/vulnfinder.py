#!/usr/bin/env python3
import argparse
import sys
import time
from urllib.parse import urlparse
from colorama import init, Fore, Style

# Internal modules
from core.recon import ReconEngine
from core.crawler import WebCrawler
from core.scanner import VulnScanner
from core.reporter import ReportGenerator

# Initialize colorama
init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.CYAN}
 __      __   _       ______ _           _           __  ___  
 \\ \\    / /  | |     |  ____(_)         | |         / / / _ \\ 
  \\ \\  / /   | |_ __ | |__   _ _ __   __| | ___ _ _| | | | | |
   \\ \\/ /| | | | '_ \\|  __| | | '_ \\ / _` |/ _ \\ '__| | | | | |
    \\  / | |_| | | | | |    | | | | | (_| |  __/ |  | | | |_| |
     \\/   \\__,_|_| |_|_|    |_|_| |_|\\__,_|\\___|_|  | |  \\___/ 
                                                     \\_\\       
{Style.RESET_ALL}
{Fore.YELLOW}  [ Automated Reconnaissance & Vulnerability Scanner ]{Style.RESET_ALL}
{Fore.GREEN}  [ Author: Zoya ]{Style.RESET_ALL}
    """
    print(banner)

def parse_args():
    parser = argparse.ArgumentParser(description="VulnFinder60 - Recon & Scanner Tool")
    parser.add_argument("-t", "--target", required=True, help="Target URL or Domain (e.g., http://example.com)")
    parser.add_argument("-o", "--output", default="vulnfinder60_report.html", help="HTML report output filename")
    parser.add_argument("--depth", type=int, default=2, help="Crawling depth (default: 2)")
    return parser.parse_args()

def normalize_target(target):
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target
    parsed = urlparse(target)
    domain = parsed.netloc
    return target, domain

def main():
    print_banner()
    args = parse_args()
    
    target_url, target_domain = normalize_target(args.target)
    print(f"{Fore.BLUE}[*] Target URL: {target_url}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Target Domain: {target_domain}{Style.RESET_ALL}")
    
    start_time = time.time()
    
    # 1. Reconnaissance
    print(f"\n{Fore.GREEN}[+] Phase 1: Reconnaissance Initiated...{Style.RESET_ALL}")
    recon_engine = ReconEngine(target_domain)
    recon_data = recon_engine.run_all()
    
    # 2. Crawling
    print(f"\n{Fore.GREEN}[+] Phase 2: Web Crawling Initiated (Depth: {args.depth})...{Style.RESET_ALL}")
    crawler = WebCrawler(target_url, max_depth=args.depth)
    crawl_data = crawler.run()
    
    # 3. Vulnerability Scanning
    print(f"\n{Fore.GREEN}[+] Phase 3: Vulnerability Scanning Initiated...{Style.RESET_ALL}")
    scanner = VulnScanner(target_url)
    vuln_data = scanner.run_all()
    
    end_time = time.time()
    duration = round(end_time - start_time, 2)
    
    # 4. Reporting
    print(f"\n{Fore.GREEN}[+] Phase 4: Report Generation...{Style.RESET_ALL}")
    reporter = ReportGenerator(target_url, recon_data, crawl_data, vuln_data, duration, args.output)
    reporter.generate_html()
    
    print(f"\n{Fore.CYAN}[=] Scan completed in {duration} seconds.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[=] Report saved to '{args.output}'.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
