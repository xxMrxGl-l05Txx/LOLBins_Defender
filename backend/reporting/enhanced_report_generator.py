"""
Enhanced report generator with multiple formats and advanced analytics
"""
import base64
import csv
import io
import json
import logging
import uuid
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional

import matplotlib
matplotlib.use('Agg')  # Headless backend; must be selected before pyplot is imported
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
from jinja2 import Environment

from ..core.database import DatabaseManager, SEVERITIES
from ..core.paths import REPORTS_DIR

logger = logging.getLogger(__name__)

REPORT_FORMATS = ('html', 'csv', 'json')
REPORT_PREFIXES = ('security_summary_', 'security_report_')

SEVERITY_COLORS = {'CRITICAL': '#e74c3c', 'HIGH': '#e67e22', 'MEDIUM': '#f39c12', 'LOW': '#27ae60'}

DEFAULT_OPTIONS = {
    'include_details': True,
    'include_mitre': True,
    'include_commands': True,
}

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Monitoring Report - {{ report_date }}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 40px; border-bottom: 3px solid #2c3e50; padding-bottom: 20px; }
        .header h1 { color: #2c3e50; margin: 0; font-size: 2.2em; }
        .header p { color: #7f8c8d; margin: 10px 0 0 0; font-size: 1.05em; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 40px; }
        .summary-card { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; font-size: 1.1em; font-weight: 500; }
        .summary-card .value { font-size: 2.4em; font-weight: bold; margin: 10px 0; }
        .summary-card .label { font-size: 0.9em; opacity: 0.85; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #2c3e50; border-left: 4px solid #3498db; padding-left: 15px; margin-bottom: 20px; }
        .chart-container { text-align: center; margin: 20px 0; }
        .chart-container img { max-width: 100%; height: auto; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .table-container { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 0.92em; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; vertical-align: top; }
        th { background-color: #f8f9fa; font-weight: 600; color: #2c3e50; }
        code { font-family: Consolas, monospace; font-size: 0.9em; word-break: break-all; }
        .severity { color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; white-space: nowrap; }
        .severity-critical { background-color: #e74c3c; }
        .severity-high { background-color: #e67e22; }
        .severity-medium { background-color: #f39c12; }
        .severity-low { background-color: #27ae60; }
        .empty { color: #7f8c8d; font-style: italic; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; }
        .recommendations { background-color: #ecf0f1; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .recommendations h3 { color: #2c3e50; margin-top: 0; }
        .recommendations ul { margin: 0 0 16px 0; padding-left: 20px; }
        .recommendations li { margin: 8px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Monitoring Report</h1>
            <p>Generated on {{ report_date }} | Period: {{ period_description }}</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Total Alerts</h3>
                <div class="value">{{ summary.total_alerts }}</div>
                <div class="label">{{ period_description }}</div>
            </div>
            <div class="summary-card">
                <h3>Critical Alerts</h3>
                <div class="value">{{ summary.critical_alerts }}</div>
                <div class="label">Require immediate attention</div>
            </div>
            <div class="summary-card">
                <h3>Risk Score</h3>
                <div class="value">{{ summary.risk_score }}</div>
                <div class="label">Out of 100</div>
            </div>
            <div class="summary-card">
                <h3>Systems</h3>
                <div class="value">{{ summary.systems_count }}</div>
                <div class="label">Reporting alerts</div>
            </div>
        </div>

        {% if charts %}
        <div class="section">
            <h2>Analytics and Trends</h2>
            {% for chart in charts %}
            <div class="chart-container">
                <h3>{{ chart.title }}</h3>
                <img src="{{ chart.data_uri }}" alt="{{ chart.title }}">
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <div class="section">
            <h2>Alerts by Type</h2>
            {% if alerts_by_type %}
            <div class="table-container">
                <table>
                    <thead><tr><th>Type</th><th>Count</th></tr></thead>
                    <tbody>
                        {% for name, count in alerts_by_type %}
                        <tr><td>{{ name }}</td><td>{{ count }}</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <p class="empty">No alerts were recorded in this period.</p>
            {% endif %}
        </div>

        {% if priority_alerts %}
        <div class="section">
            <h2>Critical and High Severity Alerts</h2>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>Binary</th>
                            {% if options.include_details %}<th>Details</th>{% endif %}
                            {% if options.include_commands %}<th>Command</th>{% endif %}
                            {% if options.include_mitre %}<th>MITRE ATT&amp;CK</th>{% endif %}
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for alert in priority_alerts %}
                        <tr>
                            <td>{{ alert.timestamp_formatted }}</td>
                            <td><span class="severity severity-{{ alert.severity|lower }}">{{ alert.severity }}</span></td>
                            <td>{{ alert.type }}</td>
                            <td>{{ alert.binary or '-' }}</td>
                            {% if options.include_details %}<td>{{ alert.details or '-' }}</td>{% endif %}
                            {% if options.include_commands %}<td><code>{{ alert.command or '-' }}</code></td>{% endif %}
                            {% if options.include_mitre %}<td>{% if alert.mitre_id %}<a href="{{ alert.mitre_link or '#' }}">{{ alert.mitre_id }}</a>{% else %}-{% endif %}</td>{% endif %}
                            <td>{{ alert.status }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}

        <div class="section">
            <h2>Recommendations</h2>
            <div class="recommendations">
                <h3>Immediate Actions</h3>
                <ul>
                    {% for rec in recommendations.immediate %}
                    <li>{{ rec }}</li>
                    {% endfor %}
                </ul>

                <h3>Long-term Improvements</h3>
                <ul>
                    {% for rec in recommendations.longterm %}
                    <li>{{ rec }}</li>
                    {% endfor %}
                </ul>
            </div>
        </div>

        <div class="footer">
            <p>This report was automatically generated by the Security Monitoring System</p>
            <p>For questions or concerns, please contact your security team</p>
        </div>
    </div>
</body>
</html>
"""

class EnhancedSecurityReportGenerator:
    """Enhanced report generator with comprehensive analytics and multiple formats"""

    def __init__(self, db_manager: DatabaseManager, output_dir: str = None):
        self.db_manager = db_manager
        self.output_dir = Path(output_dir) if output_dir else REPORTS_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Autoescape: alert commands and details come from monitored processes
        self._template = Environment(autoescape=True).from_string(REPORT_TEMPLATE)

        logger.info(f"Enhanced report generator initialized (output: {self.output_dir})")

    @staticmethod
    def _period_description(days: int) -> str:
        return f"Last {days} day{'s' if days != 1 else ''}" if days > 0 else "All time"

    @staticmethod
    def _options(options: Optional[Dict[str, Any]]) -> Dict[str, bool]:
        merged = dict(DEFAULT_OPTIONS)
        for key, value in (options or {}).items():
            if key in merged:
                merged[key] = bool(value)
        return merged

    def _new_report_path(self, prefix: str, extension: str) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return self.output_dir / f"{prefix}{timestamp}_{uuid.uuid4().hex[:6]}.{extension}"

    def _load_alerts(self, days: int = 30) -> List[Dict[str, Any]]:
        """Load alerts from the database"""
        try:
            start_time = (datetime.now() - timedelta(days=days)).timestamp() if days > 0 else None
            alerts = self.db_manager.get_alerts(limit=100000, start_time=start_time)

            for alert in alerts:
                if isinstance(alert.get('timestamp'), (int, float)):
                    alert['timestamp_formatted'] = datetime.fromtimestamp(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    alert['timestamp_formatted'] = ''

            return alerts
        except Exception as e:
            logger.error(f"Failed to load alerts: {e}")
            return []

    def _load_metrics(self, days: int = 30) -> List[Dict[str, Any]]:
        """Load metrics from the database, oldest first"""
        try:
            start_time = (datetime.now() - timedelta(days=days)).timestamp() if days > 0 else None
            metrics = self.db_manager.get_metrics(limit=100000, start_time=start_time)
            return list(reversed(metrics))
        except Exception as e:
            logger.error(f"Failed to load metrics: {e}")
            return []

    @staticmethod
    def _figure_to_data_uri(fig) -> str:
        """Render a figure as an inline PNG so the HTML report is self-contained"""
        buffer = io.BytesIO()
        fig.savefig(buffer, format='png', dpi=110, bbox_inches='tight')
        plt.close(fig)
        return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode('ascii')

    def _generate_charts(self, alerts: List[Dict[str, Any]],
                         metrics: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Generate charts for the report"""
        charts = []

        try:
            if alerts:
                counts = Counter(a.get('severity', 'UNKNOWN') for a in alerts)
                labels = [s for s in SEVERITIES if counts.get(s)] + [s for s in counts if s not in SEVERITIES]

                fig, ax = plt.subplots(figsize=(7, 6))
                ax.pie(
                    [counts[s] for s in labels],
                    labels=labels,
                    autopct='%1.1f%%',
                    colors=[SEVERITY_COLORS.get(s, '#95a5a6') for s in labels],
                    startangle=90,
                    explode=[0.05 if s in ('CRITICAL', 'HIGH') else 0 for s in labels]
                )
                ax.set_title('Alerts by Severity', fontsize=14, fontweight='bold', pad=16)
                ax.axis('equal')
                charts.append({'title': 'Alert Severity Distribution', 'data_uri': self._figure_to_data_uri(fig)})

                daily_counts = Counter(
                    datetime.fromtimestamp(a['timestamp']).date()
                    for a in alerts if isinstance(a.get('timestamp'), (int, float))
                )
                if daily_counts:
                    dates = sorted(daily_counts)
                    fig, ax = plt.subplots(figsize=(11, 4.5))
                    ax.bar(dates, [daily_counts[d] for d in dates], color='#3498db', width=0.8)
                    ax.set_title('Alerts per Day', fontsize=14, fontweight='bold', pad=16)
                    ax.set_ylabel('Number of Alerts')
                    ax.grid(True, axis='y', alpha=0.3)
                    ax.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d'))
                    fig.autofmt_xdate()
                    charts.append({'title': 'Alerts Over Time', 'data_uri': self._figure_to_data_uri(fig)})

            if metrics:
                step = max(1, len(metrics) // 300)
                sampled = metrics[::step]
                times = [datetime.fromtimestamp(m['timestamp']) for m in sampled]

                fig, axes = plt.subplots(2, 2, figsize=(13, 8))
                panels = [
                    ('cpu_percent', 'CPU Usage (%)', '#e74c3c'),
                    ('memory_percent', 'Memory Usage (%)', '#3498db'),
                    ('disk_percent', 'Disk Usage (%)', '#f39c12'),
                    ('process_count', 'Process Count', '#27ae60'),
                ]
                for ax, (key, title, color) in zip(axes.flat, panels):
                    ax.plot(times, [m.get(key) or 0 for m in sampled], color=color, linewidth=1.8)
                    ax.set_title(title, fontweight='bold')
                    ax.grid(True, alpha=0.3)
                    ax.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d %H:%M'))
                    plt.setp(ax.xaxis.get_majorticklabels(), rotation=30, ha='right')
                fig.tight_layout()
                charts.append({'title': 'System Performance Metrics', 'data_uri': self._figure_to_data_uri(fig)})

        except Exception as e:
            logger.error(f"Error generating charts: {e}")

        return charts

    def _calculate_summary_stats(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate summary statistics"""
        critical_alerts = sum(1 for a in alerts if a.get('severity') == 'CRITICAL')
        high_alerts = sum(1 for a in alerts if a.get('severity') == 'HIGH')

        return {
            'total_alerts': len(alerts),
            'critical_alerts': critical_alerts,
            'high_alerts': high_alerts,
            'risk_score': min(100, (critical_alerts * 20) + (high_alerts * 10)),
            'systems_count': len({a.get('system_name') for a in alerts if a.get('system_name')})
        }

    def _generate_recommendations(self, alerts: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Generate security recommendations based on alerts"""
        immediate = []
        alert_types = Counter(alert.get('type', 'unknown') for alert in alerts)

        longterm = []
        if alert_types.get('lolbin_detection', 0) > 0:
            immediate.append("Investigate LOLBin detections - review the command lines and parent processes involved")
            longterm.append("Implement application control (e.g. WDAC/AppLocker) to restrict LOLBin abuse")

        if alert_types.get('suspicious_network_activity', 0) > 0:
            immediate.append("Review outbound connections flagged as suspicious and block unknown destinations")

        if alert_types.get('high_cpu', 0) > 10:
            immediate.append("Investigate sustained high CPU usage - possible cryptomining or DoS attack")
            longterm.append("Tune CPU usage alert thresholds to the system's normal workload")

        if alert_types.get('high_memory', 0) > 10:
            immediate.append("Investigate memory usage patterns - possible memory leak or malware")
            longterm.append("Profile long-running processes for memory growth")

        if any(a.get('severity') == 'CRITICAL' and a.get('status') in ('new', 'acknowledged') for a in alerts):
            immediate.append("Address all open critical alerts immediately")
            immediate.append("Review and update incident response procedures")

        if not immediate:
            immediate.append("Continue monitoring - no immediate threats detected")

        longterm.extend([
            "Regular security awareness training for staff",
            "Keep all systems updated with latest security patches",
            "Implement network segmentation and access controls",
            "Regular backup and disaster recovery testing"
        ])

        return {'immediate': immediate, 'longterm': longterm}

    @staticmethod
    def _export_fields(options: Dict[str, bool]) -> List[str]:
        fields = ['timestamp', 'id', 'type', 'severity', 'status', 'binary',
                  'process_id', 'user_name', 'system_name']
        if options['include_details']:
            fields.append('details')
        if options['include_commands']:
            fields.append('command')
        if options['include_mitre']:
            fields.extend(['mitre_id', 'mitre_link'])
        return fields

    def generate(self, report_format: str, days: int = 30,
                 options: Optional[Dict[str, Any]] = None) -> Optional[Path]:
        """Generate a report in the requested format"""
        generators = {
            'html': self.generate_summary_report,
            'csv': self.generate_csv_report,
            'json': self.generate_json_report,
        }
        if report_format not in generators:
            raise ValueError(f"Unsupported report format: {report_format}")
        return generators[report_format](days=days, options=options)

    def generate_summary_report(self, days: int = 30, options: Optional[Dict[str, Any]] = None) -> Optional[Path]:
        """Generate a comprehensive, self-contained HTML summary report"""
        try:
            logger.info(f"Generating summary report ({self._period_description(days)})")
            options = self._options(options)

            alerts = self._load_alerts(days)
            metrics = self._load_metrics(days)

            priority_alerts = [a for a in alerts if a.get('severity') in ('CRITICAL', 'HIGH')][:50]

            rendered_html = self._template.render(
                report_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                period_description=self._period_description(days),
                summary=self._calculate_summary_stats(alerts),
                charts=self._generate_charts(alerts, metrics),
                alerts_by_type=Counter(a.get('type', 'unknown') for a in alerts).most_common(),
                priority_alerts=priority_alerts,
                recommendations=self._generate_recommendations(alerts),
                options=options,
            )

            report_path = self._new_report_path('security_summary_', 'html')
            report_path.write_text(rendered_html, encoding='utf-8')

            logger.info(f"Summary report generated: {report_path}")
            return report_path

        except Exception as e:
            logger.error(f"Error generating summary report: {e}")
            return None

    def generate_csv_report(self, days: int = 30, options: Optional[Dict[str, Any]] = None) -> Optional[Path]:
        """Generate a CSV report (header only when there are no alerts)"""
        try:
            logger.info(f"Generating CSV report ({self._period_description(days)})")
            options = self._options(options)
            fields = self._export_fields(options)

            alerts = self._load_alerts(days)

            csv_path = self._new_report_path('security_report_', 'csv')
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fields, extrasaction='ignore')
                writer.writeheader()
                for alert in alerts:
                    row = {field: alert.get(field) if alert.get(field) is not None else '' for field in fields}
                    row['timestamp'] = alert.get('timestamp_formatted', '')
                    writer.writerow(row)

            logger.info(f"CSV report generated: {csv_path}")
            return csv_path

        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
            return None

    def generate_json_report(self, days: int = 30, options: Optional[Dict[str, Any]] = None) -> Optional[Path]:
        """Generate a comprehensive JSON report"""
        try:
            logger.info(f"Generating JSON report ({self._period_description(days)})")
            options = self._options(options)
            fields = self._export_fields(options)

            alerts = self._load_alerts(days)
            metrics = self._load_metrics(days)

            exported_alerts = []
            for alert in alerts:
                item = {field: alert.get(field) for field in fields}
                item['timestamp_formatted'] = alert.get('timestamp_formatted')
                if options['include_details']:
                    item['metadata'] = alert.get('metadata', {})
                exported_alerts.append(item)

            report_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'period_days': days,
                    'period_description': self._period_description(days),
                    'generator_version': '2.0.0',
                    'options': options
                },
                'summary': self._calculate_summary_stats(alerts),
                'alerts': exported_alerts,
                'metrics': metrics[-100:],
                'recommendations': self._generate_recommendations(alerts),
                'statistics': {
                    'alerts_by_type': dict(Counter(a.get('type', 'unknown') for a in alerts)),
                    'alerts_by_severity': dict(Counter(a.get('severity', 'UNKNOWN') for a in alerts)),
                    'alerts_by_status': dict(Counter(a.get('status', 'new') for a in alerts)),
                    'alerts_by_system': dict(Counter(a.get('system_name') or 'Unknown' for a in alerts))
                }
            }

            json_path = self._new_report_path('security_report_', 'json')
            with open(json_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(report_data, jsonfile, indent=2, default=str)

            logger.info(f"JSON report generated: {json_path}")
            return json_path

        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            return None

    def _report_files(self) -> List[Path]:
        return [
            p for p in self.output_dir.iterdir()
            if p.is_file() and p.name.startswith(REPORT_PREFIXES) and p.suffix.lstrip('.') in REPORT_FORMATS
        ]

    def list_reports(self) -> List[Dict[str, Any]]:
        """List generated reports, newest first"""
        reports = []
        for path in self._report_files():
            stat = path.stat()
            reports.append({
                'filename': path.name,
                'format': path.suffix.lstrip('.'),
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                '_mtime': stat.st_mtime,
            })
        reports.sort(key=lambda r: r.pop('_mtime') * -1)
        return reports

    def cleanup_old_reports(self, retention_days: int = 30):
        """Clean up old report files"""
        try:
            cutoff = (datetime.now() - timedelta(days=retention_days)).timestamp()
            removed = 0
            for path in self._report_files():
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
            logger.info(f"Removed {removed} reports older than {retention_days} days")
        except Exception as e:
            logger.error(f"Error cleaning up old reports: {e}")
