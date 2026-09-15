import logging
import tkinter as tk
from tkinter import messagebox
import threading
import queue
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("TkinterNotifier")

class TkinterNotifier:
    def __init__(self):
        self.notification_queue = queue.Queue()
        self.gui_thread = None
        self._start_gui_thread()
        logger.info("Tkinter notifier initialized")
        
    def _start_gui_thread(self):
        """Start a separate thread for tkinter notifications"""
        self.gui_thread = threading.Thread(target=self._run_notification_loop, daemon=True)
        self.gui_thread.start()
        
    def _run_notification_loop(self):
        """Process notifications in a background thread"""
        while True:
            try:
                if not self.notification_queue.empty():
                    alert = self.notification_queue.get()
                    self._show_notification(alert)
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Error in notification loop: {e}")
                
    def _show_notification(self, alert):
        """Show tkinter notification popup"""
        try:
            # Create root window
            root = tk.Tk()
            root.withdraw()  # Hide the main window
            
            # Format the alert message
            title = f"Security Alert: {alert['type']}"
            severity = alert.get('severity', 'unknown').upper()
            message = f"SEVERITY: {severity}\n\n{alert.get('details', 'No details provided')}"
            
            # Show message based on severity
            if severity.lower() == "critical":
                messagebox.showerror(title, message)
            elif severity.lower() in ["high", "medium"]:
                messagebox.showwarning(title, message)
            else:
                messagebox.showinfo(title, message)
                
            root.destroy()
            logger.info(f"Displayed tkinter notification for alert: {alert['type']}")
            return True
        except Exception as e:
            logger.error(f"Failed to show tkinter notification: {e}")
            return False
            
    def send_notification(self, alert):
        """Queue an alert for display"""
        try:
            self.notification_queue.put(alert)
            logger.info(f"Queued notification for alert: {alert['type']}")
            return True
        except Exception as e:
            logger.error(f"Failed to queue notification: {e}")
            return False

if __name__ == "__main__":
    # Test the notifier
    notifier = TkinterNotifier()
    test_alert = {
        "type": "test_alert",
        "severity": "medium",
        "details": "This is a test notification from the Tkinter notifier"
    }
    notifier.send_notification(test_alert)
    
    # Keep the main thread alive to allow the notification to display
    print("Notification queued. Waiting...")
    time.sleep(10)
