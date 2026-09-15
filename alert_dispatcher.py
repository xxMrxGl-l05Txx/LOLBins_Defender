import tkinter as tk
from tkinter import messagebox
import json
import os

class AlertNotifier:
    """Base class for alert notifiers"""
    def notify(self, alert_data):
        """Send notification with alert data"""
        raise NotImplementedError("Subclasses must implement notify()")

class TkinterNotifier(AlertNotifier):
    """Displays alert using tkinter popup"""
    def notify(self, alert_data):
        root = tk.Tk()
        root.withdraw()  # Hide the main window
        
        severity = alert_data.get("severity", "UNKNOWN")
        binary = alert_data.get("binary", "Unknown binary")
        command = alert_data.get("command", "Unknown command")
        
        title = f"LOLBin Alert - {severity}"
        message = f"Detected potential malicious use of {binary}\n\nCommand: {command}\n\nSeverity: {severity}"
        
        messagebox.showwarning(title, message)
        
        # Ensure application exits properly
        root.destroy()
        return True

class AlertDispatcher:
    """Dispatches alerts to all registered notifiers"""
    def __init__(self):
        self.notifiers = []
    
    def register_notifier(self, notifier):
        """Register a new alert notifier"""
        if not isinstance(notifier, AlertNotifier):
            raise TypeError("Notifier must be an instance of AlertNotifier")
        self.notifiers.append(notifier)
    
    def dispatch_alert(self, alert_data):
        """Send alert to all registered notifiers"""
        results = []
        
        for notifier in self.notifiers:
            try:
                success = notifier.notify(alert_data)
                results.append(success)
            except Exception as e:
                print(f"Error in notifier {notifier.__class__.__name__}: {e}")
                results.append(False)
        
        # Save alert to a JSON file for historic record
        self._save_alert(alert_data)
        
        return all(results)  # Return True only if all notifications were successful
    
    def _save_alert(self, alert_data):
        """Save alert to JSON file for history tracking"""
        alerts_file = "lolbin_alerts_history.json"
        alerts = []
        
        # Load existing alerts if file exists
        if os.path.exists(alerts_file):
            try:
                with open(alerts_file, 'r') as f:
                    alerts = json.load(f)
            except json.JSONDecodeError:
                alerts = []
        
        # Add new alert
        alerts.append(alert_data)
        
        # Save back to file
        with open(alerts_file, 'w') as f:
            json.dump(alerts, f, indent=2)
