# VulnFinder60
**Author**: Zoya
**Version**: 1.0.0

VulnFinder60 is a modular, automated reconnaissance and vulnerability scanning tool. It combines custom port scanning, recursive crawling, DNS recon, and industry standard vulnerability scanners (`nikto`, `nuclei`) into a single slick pipeline. The final output is an elegantly designed HTML report with a cyberpunk security theme.

## Features
- **Reconnaissance**: Subdomains, DNS records, Port scanning.
- **Crawling**: Recursive multithreaded spidering, parameter extraction, JS file discovery.
- **Vulnerability Scanning**: Automated runs for Nikto and Nuclei.
- **Reporting**: Beautiful HTML reports using Jinja2 templates.
- **Modularity**: Easy to extend and maintain.

## Installation

### Method 1: Local PyPI Install
```bash
# Clone the repository
git clone https://github.com/yourusername/VulnFinder60.git
cd VulnFinder60

# Install dependencies (virtual env recommended)
python3 -m venv venv
source venv/bin/activate

# Install the package
pip install -e .

# Make sure nikto and nuclei are installed on your OS:
# e.g., sudo apt install nikto
# go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Method 2: Docker (Recommended)
```bash
docker build -t vulnfinder60 .
docker run --rm -v $(pwd)/reports:/app/reports vulnfinder60 -t http://example.com
```

## Usage
```bash
# Basic scan
vulnfinder60 -t http://example.com

# Specify output report name
vulnfinder60 -t http://example.com -o target_report.html
```

## Ethical Guidelines & Disclaimer
Do **NOT** use this tool on a target without explicit authorization. Do not perform DoS attacks or destructive exploitation. The author (Zoya) is not responsible for any misuse.
