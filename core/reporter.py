import os
import datetime
from jinja2 import Environment, FileSystemLoader

class ReportGenerator:
    def __init__(self, target, recon_data, crawl_data, vuln_data, duration, output_file):
        self.target = target
        self.recon_data = recon_data
        self.crawl_data = crawl_data
        self.vuln_data = vuln_data
        self.duration = duration
        self.output_file = output_file
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')

    def aggregate_severity_counts(self):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        
        for v in self.vuln_data.get("nuclei", []):
            sev = v.get("severity", "Info")
            if sev in counts:
                counts[sev] += 1
                
        # Basic parsing for Nikto (assigned medium contextually)
        counts["Medium"] += len([n for n in self.vuln_data.get("nikto", []) if n.get("severity") != "Info"])
        return counts

    def generate_html(self):
        env = Environment(loader=FileSystemLoader(self.template_dir))
        template = env.get_template('report_template.html')
        
        counts = self.aggregate_severity_counts()
        
        html_content = template.render(
            target=self.target,
            timestamp=self.timestamp,
            duration=self.duration,
            recon=self.recon_data,
            crawl=self.crawl_data,
            vulns=self.vuln_data,
            counts=counts
        )
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
