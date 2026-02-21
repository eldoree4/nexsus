import json
import csv
import os
from datetime import datetime
from nexsus.config import Config

class ReportGenerator:
    @staticmethod
    def generate(findings, assets):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"nexsus_report_{timestamp}"

        with open(os.path.join(Config.REPORT_DIR, f"{base_name}.json"), 'w') as f:
            json.dump(findings, f, indent=2)

        with open(os.path.join(Config.REPORT_DIR, f"{base_name}.csv"), 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ID', 'Title', 'Severity', 'Asset', 'Endpoint', 'Parameter', 'Confidence', 'Impact', 'Remediation'])
            for fnd in findings:
                writer.writerow([
                    fnd.get('id',''),
                    fnd.get('title',''),
                    fnd.get('severity',''),
                    fnd.get('asset',''),
                    fnd.get('endpoint',''),
                    fnd.get('parameter',''),
                    fnd.get('confidence',''),
                    fnd.get('impact_summary',''),
                    fnd.get('remediation','')
                ])

        html = f"""<!DOCTYPE html>
<html>
<head><title>Nexsus Report</title>
<style>
body {{ font-family: Arial; margin: 20px; }}
h1 {{ color: #333; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background-color: #f2f2f2; }}
.critical {{ color: red; font-weight: bold; }}
.high {{ color: orange; }}
.medium {{ color: gold; }}
.low {{ color: blue; }}
.info {{ color: gray; }}
</style>
</head>
<body>
<h1>Nexsus Security Assessment Report</h1>
<p>Generated: {datetime.now()}</p>
<h2>Findings Summary</h2>
<table>
<tr><th>ID</th><th>Title</th><th>Severity</th><th>Asset</th></tr>
"""
        for fnd in findings:
            sev_class = fnd.get('severity','').lower()
            html += f"<tr><td>{fnd.get('id','')}</td><td>{fnd.get('title','')}</td><td class='{sev_class}'>{fnd.get('severity','')}</td><td>{fnd.get('asset','')}</td></tr>"
        html += "</table></body></html>"
        with open(os.path.join(Config.REPORT_DIR, f"{base_name}.html"), 'w') as f:
            f.write(html)

        print(f"[+] Reports saved to {Config.REPORT_DIR}")
