import socket
import concurrent.futures
import dns.resolver
from colorama import Fore

class ReconEngine:
    def __init__(self, domain):
        self.domain = domain
        self.results = {
            "ip_addresses": [],
            "open_ports": [],
            "dns_records": {},
            "subdomains": []
        }
    
    def resolve_dns(self):
        print(f"{Fore.YELLOW} [*] Resolving DNS records for {self.domain}...{Fore.RESET}")
        try:
            # A records
            a_records = dns.resolver.resolve(self.domain, 'A')
            self.results["ip_addresses"] = [ip.to_text() for ip in a_records]
            
            # MX records
            try:
                mx_records = dns.resolver.resolve(self.domain, 'MX')
                self.results["dns_records"]['MX'] = [mx.to_text() for mx in mx_records]
            except Exception:
                pass
                
            # TXT records
            try:
                txt_records = dns.resolver.resolve(self.domain, 'TXT')
                self.results["dns_records"]['TXT'] = [txt.to_text() for txt in txt_records]
            except Exception:
                pass
                
        except Exception as e:
            print(f"{Fore.RED} [!] DNS Resolution failed: {e}{Fore.RESET}")

    def scan_port(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                self.results["open_ports"].append(port)
            s.close()
        except:
            pass

    def port_scan(self):
        print(f"{Fore.YELLOW} [*] Performing fast port scan (Top ports)...{Fore.RESET}")
        top_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        if not self.results["ip_addresses"]:
            return
            
        target_ip = self.results["ip_addresses"][0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for port in top_ports:
                executor.submit(self.scan_port, target_ip, port)

    def find_subdomains(self):
        # Simulated subdomain discovery using crt.sh or similar could go here.
        # For assignment safety & speed, we append a few common ones if they resolve.
        print(f"{Fore.YELLOW} [*] Enumerating common subdomains...{Fore.RESET}")
        common_subs = ["www", "mail", "dev", "staging", "api", "test"]
        for sub in common_subs:
            subdomain = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(subdomain)
                self.results["subdomains"].append(subdomain)
            except:
                pass

    def run_all(self):
        self.resolve_dns()
        self.port_scan()
        self.find_subdomains()
        return self.results
