import json
import logging
import os
import time
from datetime import datetime
import subprocess
import threading

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("AlertDispatcher")

class AlertDispatcher:
    def __init__(self, alerts_log_path=None):
        self.alerts_log_path = alerts_log_path or os.path.join(os.path.dirname(__file__), "alerts_log.json")
        self.notifiers = {}
        self._load_alert_history()
        logger.info("Alert dispatcher initialized")
        
    def _load_alert_history(self):
        """Load alert history from log file"""
        try:
            if os.path.exists(self.alerts_log_path):
                with open(self.alerts_log_path, 'r') as f:
                    data = json.load(f)
                    # Fix: support both list and dict structure
                    if isinstance(data, dict) and "alerts" in data:
                        self.alert_history = data["alerts"]
                    elif isinstance(data, list):
                        self.alert_history = data
                    else:
                        self.alert_history = []
            else:
                self.alert_history = []
        except Exception as e:
            logger.error(f"Failed to load alert history: {e}")
            self.alert_history = []
            
    def _save_alert_history(self):
        """Save alert history to log file"""
        try:
            with open(self.alerts_log_path, 'w') as f:
                json.dump({"alerts": self.alert_history}, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save alert history: {e}")
            
    def register_notifier(self, name, notifier):
        """Register a notification service"""
        self.notifiers[name] = notifier
        logger.info(f"Registered notifier: {name}")
        
    def dispatch_alert(self, alert):
        """Dispatch alert to all registered notifiers"""
        if not alert:
            return False
            
        # Add timestamp and ID if not present
        if "timestamp" not in alert:
            alert["timestamp"] = datetime.now().isoformat()
        if "id" not in alert:
            alert["id"] = f"alert-{int(time.time())}-{len(self.alert_history)}"
            
        logger.info(f"Dispatching alert: {alert['type']} (ID: {alert['id']})")
        
        # Add to history
        self.alert_history.append(alert)
        self._save_alert_history()
        
        # Dispatch to all notifiers
        dispatch_results = {}
        for name, notifier in self.notifiers.items():
            try:
                success = notifier.send_notification(alert)
                dispatch_results[name] = success
                logger.info(f"Alert sent to {name}: {'success' if success else 'failed'}")
            except Exception as e:
                logger.error(f"Failed to send alert to {name}: {e}")
                dispatch_results[name] = False
                
        return dispatch_results
        
    def dispatch_bulk_alerts(self, alerts):
        """Dispatch multiple alerts"""
        results = []
        for alert in alerts:
            results.append(self.dispatch_alert(alert))
        return results

if __name__ == "__main__":
    # Example usage
    from tkinter_notifier import TkinterNotifier
    
    dispatcher = AlertDispatcher()
    dispatcher.register_notifier("tkinter", TkinterNotifier())
    
    test_alert = {
        "type": "high_cpu",
        "severity": "medium",
        "details": "CPU usage at 95% for over 5 minutes",
    }
    
    dispatcher.dispatch_alert(test_alert)
