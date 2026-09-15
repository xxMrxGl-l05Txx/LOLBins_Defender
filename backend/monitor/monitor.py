import json
import os
import time
import logging
import psutil
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Monitor")

class SecurityMonitor:
    def __init__(self, rules_file=None):
        self.rules_file = rules_file or os.path.join(os.path.dirname(__file__), "rules.json")
        self.rules = self._load_rules()
        self.collected_data = {}
        logger.info("Security monitor initialized")

    def _load_rules(self):
        try:
            with open(self.rules_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            return {"cpu_threshold": 80, "memory_threshold": 80, "monitor_interval": 60}

    def collect_system_metrics(self):
        """Collect system performance metrics"""
        metrics = {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "timestamp": time.time()
        }
        self.collected_data = metrics
        return metrics

    def check_thresholds(self, metrics):
        """Check if any metrics exceed defined thresholds"""
        alerts = []
        if metrics["cpu_percent"] > self.rules.get("cpu_threshold", 80):
            alerts.append({"type": "high_cpu", "value": metrics["cpu_percent"]})
            
        if metrics["memory_percent"] > self.rules.get("memory_threshold", 80):
            alerts.append({"type": "high_memory", "value": metrics["memory_percent"]})
            
        return alerts

    def run_monitoring_cycle(self):
        """Run a complete monitoring cycle"""
        logger.info("Starting monitoring cycle")
        metrics = self.collect_system_metrics()
        alerts = self.check_thresholds(metrics)
        return {"metrics": metrics, "alerts": alerts}

if __name__ == "__main__":
    monitor = SecurityMonitor()
    while True:
        result = monitor.run_monitoring_cycle()
        if result["alerts"]:
            logger.warning(f"Alerts detected: {result['alerts']}")
        time.sleep(monitor.rules.get("monitor_interval", 60))
