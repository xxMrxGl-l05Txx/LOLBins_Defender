import json
import os
import sys
import logging
from datetime import datetime, timedelta
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ReportGenerator")

class SecurityReportGenerator:
    def __init__(self, output_dir=None):
        self.output_dir = output_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        self.alerts_log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                          "alerting", "alerts_log.json")
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        logger.info("Report generator initialized")
        
    def _load_alerts(self, days=30):
        """Load alerts from the past X days"""
        try:
            if os.path.exists(self.alerts_log_path):
                with open(self.alerts_log_path, 'r') as f:
                    data = json.load(f)
                    alerts = data.get("alerts", []) if isinstance(data, dict) else data
                    
                # Filter by date if timestamps are available
                if days > 0:
                    cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
                    alerts = [a for a in alerts if a.get('timestamp', '') >= cutoff_date]
                    
                return alerts
            return []
        except Exception as e:
            logger.error(f"Failed to load alerts: {e}")
            return []
    
    def generate_summary_report(self, days=30):
        """Generate a summary report of recent security alerts"""
        logger.info(f"Generating summary report for the past {days} days")
        
        alerts = self._load_alerts(days)
        if not alerts:
            logger.warning("No alerts found for the specified period")
            return None
            
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(alerts)
        
        # Generate report filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"security_summary_{timestamp}.html"
        report_path = os.path.join(self.output_dir, report_filename)
        
        # Create HTML report content
        html_content = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "    <title>Security Alert Summary Report</title>",
            "    <style>",
            "        body { font-family: Arial, sans-serif; margin: 20px; }",
            "        h1, h2 { color: #2c3e50; }",
            "        table { border-collapse: collapse; width: 100%; }",
            "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
            "        th { background-color: #f2f2f2; }",
            "        tr:nth-child(even) { background-color: #f9f9f9; }",
            "        .critical { color: #e74c3c; font-weight: bold; }",
            "        .high { color: #e67e22; font-weight: bold; }",
            "        .medium { color: #f1c40f; }",
            "        .low { color: #2ecc71; }",
            "    </style>",
            "</head>",
            "<body>",
            f"    <h1>Security Alert Summary Report</h1>",
            f"    <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            f"    <p>Covering period: {(datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')} to {datetime.now().strftime('%Y-%m-%d')}</p>",
            f"    <h2>Alert Summary</h2>"
        ]
        
        # Add summary statistics
        alert_count = len(df)
        html_content.extend([
            f"    <p>Total alerts: {alert_count}</p>"
        ])
        
        # Add severity breakdown if available
        if 'severity' in df.columns:
            severity_counts = df['severity'].value_counts()
            html_content.extend([
                "    <h3>Alerts by Severity</h3>",
                "    <table>",
                "        <tr><th>Severity</th><th>Count</th></tr>"
            ])
            
            for severity, count in severity_counts.items():
                html_content.append(f"        <tr><td class='{severity.lower()}'>{severity}</td><td>{count}</td></tr>")
                
            html_content.append("    </table>")
            
            # Generate and save severity pie chart
            plt.figure(figsize=(8, 8))
            plt.pie(severity_counts, labels=severity_counts.index, autopct='%1.1f%%', 
                    colors=['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71'])
            plt.title('Alerts by Severity')
            chart_path = os.path.join(self.output_dir, f"severity_chart_{timestamp}.png")
            plt.savefig(chart_path)
            plt.close()
            
            html_content.extend([
                "    <h3>Severity Distribution</h3>",
                f"    <img src='{os.path.basename(chart_path)}' alt='Severity Distribution Chart' />"
            ])
            
        # Add type breakdown
        if 'type' in df.columns:
            type_counts = df['type'].value_counts()
            html_content.extend([
                "    <h3>Alerts by Type</h3>",
                "    <table>",
                "        <tr><th>Alert Type</th><th>Count</th></tr>"
            ])
            
            for alert_type, count in type_counts.items():
                html_content.append(f"        <tr><td>{alert_type}</td><td>{count}</td></tr>")
                
            html_content.append("    </table>")
            
        # Add recent critical alerts
        if 'severity' in df.columns and 'critical' in df['severity'].values:
            critical_alerts = df[df['severity'] == 'critical'].sort_values('timestamp', ascending=False)
            if not critical_alerts.empty:
                html_content.extend([
                    "    <h3>Recent Critical Alerts</h3>",
                    "    <table>",
                    "        <tr><th>Timestamp</th><th>Type</th><th>Details</th></tr>"
                ])
                
                for _, alert in critical_alerts.iterrows():
                    html_content.append(f"        <tr><td>{alert.get('timestamp', 'N/A')}</td><td>{alert.get('type', 'N/A')}</td><td>{alert.get('details', 'N/A')}</td></tr>")
                    
                html_content.append("    </table>")
                
        # Close HTML document
        html_content.extend([
            "</body>",
            "</html>"
        ])
        
        # Write report to file
        with open(report_path, 'w') as f:
            f.write('\n'.join(html_content))
            
        logger.info(f"Report saved to {report_path}")
        return report_path
    
    def generate_detailed_report(self, start_date=None, end_date=None):
        """Generate a detailed security report for a specific time period"""
        # Implementation would be similar to summary report but with more details
        pass
        
    def generate_csv_report(self, days=30):
        """Generate a CSV report containing all alert fields
        
        Args:
            days (int): Number of days to include in the report, default is 30
            
        Returns:
            str: Path to the generated CSV file or None if no alerts found
        """
        logger.info(f"Generating CSV report for the past {days} days")
        
        alerts = self._load_alerts(days)
        if not alerts:
            logger.warning("No alerts found for the specified period")
            return None
            
        # Convert to DataFrame
        df = pd.DataFrame(alerts)
        
        # Ensure all required fields are present (filling NaN for missing values)
        required_fields = ['timestamp', 'type', 'severity', 'binary', 'command', 'mitre_id', 'mitre_link']
        for field in required_fields:
            if field not in df.columns:
                df[field] = 'N/A'
        
        # Generate CSV filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_filename = f"security_report_{timestamp}.csv"
        csv_path = os.path.join(self.output_dir, csv_filename)
        
        # Write to CSV
        df.to_csv(csv_path, index=False)
        
        logger.info(f"CSV report saved to {csv_path}")
        return csv_path
        
if __name__ == "__main__":
    generator = SecurityReportGenerator()
    report_path = generator.generate_summary_report(days=30)
    if report_path:
        print(f"Report generated: {report_path}")
    else:
        print("Failed to generate report")
