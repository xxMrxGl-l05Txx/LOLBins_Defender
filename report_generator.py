import matplotlib.pyplot as plt
import json
import os
from datetime import datetime
from collections import Counter
import base64
from io import BytesIO

class ReportGenerator:
    def __init__(self, alerts_file="lolbin_alerts_history.json"):
        self.alerts_file = alerts_file
        self.alerts = self._load_alerts()
    
    def _load_alerts(self):
        """Load alerts from JSON file"""
        if not os.path.exists(self.alerts_file):
            return []
            
        try:
            with open(self.alerts_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"Error loading alerts from {self.alerts_file}")
            return []
    
    def generate_severity_pie_chart(self, save_path=None):
        """
        Generate pie chart showing alert distribution by severity
        """
        if not self.alerts:
            print("No alerts to generate chart from")
            return None
        
        # Count alerts by severity
        severity_counts = Counter(alert.get('severity', 'UNKNOWN') for alert in self.alerts)
        
        # Create labels and sizes for pie chart
        labels = list(severity_counts.keys())
        sizes = list(severity_counts.values())
        
        # Define colors for different severity levels
        colors = {
            'CRITICAL': 'darkred',
            'HIGH': 'red',
            'MEDIUM': 'orange',
            'LOW': 'yellow',
            'UNKNOWN': 'gray'
        }
        
        # Map severity levels to colors
        chart_colors = [colors.get(severity, 'gray') for severity in labels]
        
        # Create figure and axis
        fig, ax = plt.subplots(figsize=(8, 6))
        
        # Create pie chart
        wedges, texts, autotexts = ax.pie(
            sizes, 
            labels=labels, 
            colors=chart_colors,
            autopct='%1.1f%%',
            startangle=90,
            explode=[0.05 if label in ['CRITICAL', 'HIGH'] else 0 for label in labels]
        )
        
        # Customize text appearance
        for text in texts:
            text.set_fontsize(12)
        
        for autotext in autotexts:
            autotext.set_fontsize(10)
            autotext.set_color('white')
        
        # Equal aspect ratio ensures pie chart is circular
        ax.axis('equal')
        
        # Add title
        total_alerts = sum(sizes)
        plt.title(f'LOLBin Alerts by Severity (Total: {total_alerts})', fontsize=14)
        
        if save_path:
            # Save to file
            plt.savefig(save_path, bbox_inches='tight', dpi=300)
            plt.close()
            return save_path
        else:
            # Return as base64 encoded string for HTML embedding
            buffer = BytesIO()
            plt.savefig(buffer, format='png', bbox_inches='tight', dpi=150)
            plt.close()
            
            # Encode the image as base64 string
            img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
            return f"data:image/png;base64,{img_str}"
    
    def generate_alerts_table(self, save_path=None):
        """
        Generate HTML table showing alert information
        
        Args:
            save_path: Optional path to save the HTML table to a file
            
        Returns:
            HTML string containing the formatted table
        """
        if not self.alerts:
            print("No alerts to generate table from")
            return None
            
        # Sort alerts by timestamp (newest first)
        sorted_alerts = sorted(self.alerts, key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Create HTML table
        html = '<table border="1" class="dataframe">\n'
        html += '  <thead>\n'
        html += '    <tr style="text-align: center;">\n'
        html += '      <th>Timestamp</th>\n'
        html += '      <th>LOLBin</th>\n'
        html += '      <th>Command</th>\n'
        html += '      <th>Process ID</th>\n'
        html += '      <th>Severity</th>\n'
        html += '    </tr>\n'
        html += '  </thead>\n'
        html += '  <tbody>\n'
        
        # Add rows
        for alert in sorted_alerts:
            timestamp = alert.get('timestamp', 'Unknown')
            lolbin = alert.get('lolbin_name', 'Unknown')
            command = alert.get('command', 'Unknown')
            pid = alert.get('pid', 'Unknown')
            severity = alert.get('severity', 'UNKNOWN')
            
            # Set row color based on severity
            row_color = {
                'CRITICAL': '#ffcccc',
                'HIGH': '#ffe6cc',
                'MEDIUM': '#ffffcc',
                'LOW': '#e6ffcc',
                'UNKNOWN': '#f2f2f2'
            }.get(severity, '#f2f2f2')
            
            html += f'    <tr style="background-color: {row_color};">\n'
            html += f'      <td>{timestamp}</td>\n'
            html += f'      <td>{lolbin}</td>\n'
            html += f'      <td>{command}</td>\n'
            html += f'      <td>{pid}</td>\n'
            html += f'      <td>{severity}</td>\n'
            html += '    </tr>\n'
        
        html += '  </tbody>\n'
        html += '</table>'
        
        if save_path:
            with open(save_path, 'w') as f:
                f.write(html)
            return save_path
            
        return html
    
    def generate_critical_alerts_list(self, severity_levels=None, save_path=None):
        """
        Generate a list of critical alerts
        
        Args:
            severity_levels: List of severity levels to include (default: CRITICAL and HIGH)
            save_path: Optional path to save the list to a file
            
        Returns:
            HTML string containing the formatted critical alerts list
        """
        if severity_levels is None:
            severity_levels = ['CRITICAL', 'HIGH']
            
        if not self.alerts:
            print("No alerts to generate critical list from")
            return None
            
        # Filter alerts by severity
        critical_alerts = [alert for alert in self.alerts 
                          if alert.get('severity', 'UNKNOWN') in severity_levels]
        
        # Sort by timestamp (newest first)
        critical_alerts = sorted(critical_alerts, key=lambda x: x.get('timestamp', ''), reverse=True)
        
        if not critical_alerts:
            return "<p>No critical alerts found.</p>"
            
        # Create HTML list
        html = f'<h2>Critical Alerts ({len(critical_alerts)})</h2>\n'
        html += '<ul class="critical-alerts">\n'
        
        for alert in critical_alerts:
            timestamp = alert.get('timestamp', 'Unknown time')
            lolbin = alert.get('lolbin_name', 'Unknown LOLBin')
            command = alert.get('command', 'Unknown command')
            severity = alert.get('severity', 'UNKNOWN')
            
            html += f'  <li class="severity-{severity.lower()}">\n'
            html += f'    <strong>{timestamp}</strong>: {lolbin} ({severity})<br>\n'
            html += f'    <code>{command}</code>\n'
            html += '  </li>\n'
        
        html += '</ul>'
        
        if save_path:
            with open(save_path, 'w') as f:
                f.write(html)
            return save_path
            
        return html
