from flask import Flask, jsonify, request, Response, send_file
import json
import os
import sys
import logging
from datetime import datetime

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import report generator
from reporting.report_generator import SecurityReportGenerator

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("APIServer")

app = Flask(__name__)

class SecurityAPIServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.alerts_log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                          "alerting", "alerts_log.json")
        self.rules_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                     "monitor", "rules.json")
        logger.info("API server initialized")
        
    def _load_alerts(self):
        """Load alerts from alerts log"""
        try:
            if os.path.exists(self.alerts_log_path):
                with open(self.alerts_log_path, 'r') as f:
                    data = json.load(f)
                    return data.get("alerts", []) if isinstance(data, dict) else data
            return []
        except Exception as e:
            logger.error(f"Failed to load alerts: {e}")
            return []
            
    def _load_rules(self):
        """Load monitoring rules"""
        try:
            if os.path.exists(self.rules_path):
                with open(self.rules_path, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            return {}
            
    def _save_rules(self, rules):
        """Save updated rules"""
        try:
            with open(self.rules_path, 'w') as f:
                json.dump(rules, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save rules: {e}")
            return False
    
    def start(self):
        """Start the API server"""
        logger.info(f"Starting API server on {self.host}:{self.port}")
        app.run(host=self.host, port=self.port)
        
# API routes
@app.route('/status', methods=['GET'])
def status():
    """Return system status"""
    return jsonify({
        "status": "running",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/alerts', methods=['GET'])
def alerts():
    """Return alerts, with optional filtering"""
    api_server = app.config['api_server']
    alerts = api_server._load_alerts()
    
    # Filter by severity if specified
    severity = request.args.get('severity')
    if severity:
        alerts = [a for a in alerts if a.get('severity') == severity]
        
    # Filter by date range if specified
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    if start_date and end_date:
        filtered_alerts = []
        for alert in alerts:
            alert_date = alert.get('timestamp', '')
            if alert_date and start_date <= alert_date <= end_date:
                filtered_alerts.append(alert)
        alerts = filtered_alerts
        
    # Limit results if specified
    limit = request.args.get('limit')
    if limit and limit.isdigit():
        alerts = alerts[:int(limit)]
        
    return jsonify({"alerts": alerts, "count": len(alerts)})

@app.route('/rules', methods=['GET', 'PUT'])
def rules():
    """Get or update monitoring rules"""
    api_server = app.config['api_server']
    
    if request.method == 'GET':
        return jsonify(api_server._load_rules())
    elif request.method == 'PUT':
        if not request.is_json:
            return jsonify({"error": "Invalid JSON"}), 400
            
        updated_rules = request.get_json()
        if api_server._save_rules(updated_rules):
            return jsonify({"status": "success", "rules": updated_rules})
        else:
            return jsonify({"error": "Failed to update rules"}), 500

@app.route('/trigger-scan', methods=['POST'])
def trigger_scan():
    """Trigger an immediate scan"""
    # This would integrate with the monitor component
    return jsonify({
        "status": "scan_initiated",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/download-csv', methods=['GET'])
def download_csv_report():
    """Generate and download a CSV report of security alerts"""
    try:
        # Get days parameter (default to 30 if not provided)
        days = request.args.get('days', default=30, type=int)
        
        # Create report generator
        report_generator = SecurityReportGenerator()
        
        # Generate CSV report
        csv_path = report_generator.generate_csv_report(days=days)
        
        if not csv_path or not os.path.exists(csv_path):
            return jsonify({"error": "Failed to generate CSV report"}), 500
            
        # Return the file for download
        return send_file(
            csv_path,
            mimetype='text/csv',
            as_attachment=True,
            download_name=os.path.basename(csv_path)
        )
        
    except Exception as e:
        logger.error(f"Error generating CSV report: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    api_server = SecurityAPIServer()
    app.config['api_server'] = api_server
    api_server.start()
