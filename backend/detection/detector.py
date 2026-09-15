import json
import logging
import os
import time
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Detector")

class SecurityDetector:
    def __init__(self):
        self.alert_history = []
        self.detection_rules = {
            "sustained_high_cpu": {"threshold": 80, "duration": 300},
            "memory_leak": {"threshold_increase": 5, "timespan": 600},
            "brute_force": {"failed_logins": 5, "timespan": 300}
        }
        logger.info("Security detector initialized")

    def analyze_metrics(self, metrics_history):
        """Analyze metrics history to detect patterns indicating security issues"""
        if not metrics_history or len(metrics_history) < 2:
            return []
        
        detections = []
        
        # Check for sustained high CPU
        recent_cpu = [m["cpu_percent"] for m in metrics_history[-5:]]
        if all(cpu > self.detection_rules["sustained_high_cpu"]["threshold"] for cpu in recent_cpu):
            detections.append({
                "type": "sustained_high_cpu",
                "severity": "medium",
                "details": f"CPU usage above {self.detection_rules['sustained_high_cpu']['threshold']}% for extended period",
                "timestamp": datetime.now().isoformat()
            })
            
        # Check for memory leak pattern
        memory_values = [m["memory_percent"] for m in metrics_history[-10:]]
        if len(memory_values) >= 10:
            if all(memory_values[i] < memory_values[i+1] for i in range(len(memory_values)-1)):
                increase = memory_values[-1] - memory_values[0]
                if increase > self.detection_rules["memory_leak"]["threshold_increase"]:
                    detections.append({
                        "type": "possible_memory_leak",
                        "severity": "high",
                        "details": f"Memory usage steadily increasing by {increase}% over time",
                        "timestamp": datetime.now().isoformat()
                    })
        
        return detections
        
    def correlate_events(self, alerts, system_metrics):
        """Correlate multiple alerts to identify complex security incidents"""
        correlated_incidents = []
        
        # Group alerts by type
        alert_types = {}
        for alert in alerts:
            if alert["type"] not in alert_types:
                alert_types[alert["type"]] = []
            alert_types[alert["type"]].append(alert)
            
        # Check for DoS attack pattern (high CPU + high network + multiple connection alerts)
        if "high_cpu" in alert_types and "high_network" in alert_types and len(alerts) > 5:
            correlated_incidents.append({
                "type": "possible_dos_attack",
                "severity": "critical",
                "related_alerts": [a["id"] for a in alerts[-5:]],
                "timestamp": datetime.now().isoformat()
            })
            
        return correlated_incidents
        
    def detect_threats(self, metrics_history, recent_alerts):
        """Main method to detect threats from monitoring data"""
        logger.info("Starting threat detection cycle")
        
        # Step 1: Analyze metrics for anomalies
        metric_detections = self.analyze_metrics(metrics_history)
        
        # Step 2: Correlate recent alerts
        correlated_incidents = self.correlate_events(recent_alerts, metrics_history[-1] if metrics_history else {})
        
        # Combine all detections
        all_detections = metric_detections + correlated_incidents
        
        if all_detections:
            logger.warning(f"Detected {len(all_detections)} potential threats")
            
        return all_detections

if __name__ == "__main__":
    detector = SecurityDetector()
    # Example test data
    metrics_history = [
        {"cpu_percent": 85, "memory_percent": 70, "timestamp": time.time() - 300},
        {"cpu_percent": 87, "memory_percent": 75, "timestamp": time.time() - 240},
        {"cpu_percent": 90, "memory_percent": 80, "timestamp": time.time() - 180},
        {"cpu_percent": 92, "memory_percent": 85, "timestamp": time.time() - 120},
        {"cpu_percent": 95, "memory_percent": 90, "timestamp": time.time() - 60}
    ]
    threats = detector.detect_threats(metrics_history, [])
    print(f"Detected threats: {threats}")
