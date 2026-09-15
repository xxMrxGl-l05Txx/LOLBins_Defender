import os
import sys
import time
import logging
import threading
import json
import signal
import argparse
from datetime import datetime

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import components
from monitor.monitor import SecurityMonitor
from detection.detector import SecurityDetector
from alerting.alert_dispatcher import AlertDispatcher
from alerting.tkinter_notifier import TkinterNotifier
from api.api_server import SecurityAPIServer
from reporting.report_generator import SecurityReportGenerator

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ServiceRunner")

class SecurityServiceRunner:
    def __init__(self):
        self.running = False
        self.threads = {}
        self.metrics_history = []
        self.recent_alerts = []
        
        # Initialize components
        self.monitor = SecurityMonitor()
        self.detector = SecurityDetector()
        self.alert_dispatcher = AlertDispatcher()
        self.api_server = SecurityAPIServer()
        self.report_generator = SecurityReportGenerator()
        
        # Register notifiers
        self.alert_dispatcher.register_notifier("tkinter", TkinterNotifier())
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        logger.info("Security service runner initialized")
        
    def signal_handler(self, sig, frame):
        """Handle termination signals"""
        logger.info(f"Received signal {sig}, shutting down...")
        self.stop()
        
    def start_monitoring_thread(self):
        """Start the monitoring thread"""
        def monitor_loop():
            logger.info("Monitoring thread started")
            while self.running:
                try:
                    result = self.monitor.run_monitoring_cycle()
                    self.metrics_history.append(result["metrics"])
                    
                    # Keep metrics history at a reasonable size
                    if len(self.metrics_history) > 1000:
                        self.metrics_history = self.metrics_history[-1000:]
                        
                    # Check for alerts
                    if result["alerts"]:
                        self.alert_dispatcher.dispatch_bulk_alerts(result["alerts"])
                        self.recent_alerts.extend(result["alerts"])
                        
                    # Run detection on collected metrics
                    detected_threats = self.detector.detect_threats(self.metrics_history, self.recent_alerts)
                    if detected_threats:
                        self.alert_dispatcher.dispatch_bulk_alerts(detected_threats)
                        self.recent_alerts.extend(detected_threats)
                        
                    # Keep recent alerts at a reasonable size
                    if len(self.recent_alerts) > 100:
                        self.recent_alerts = self.recent_alerts[-100:]
                        
                    # Sleep according to monitor interval
                    time.sleep(self.monitor.rules.get("monitor_interval", 60))
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}")
                    time.sleep(5)  # Sleep a bit before retrying
                    
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
        self.threads["monitor"] = thread
        
    def start_api_thread(self):
        """Start the API server thread"""
        def api_loop():
            try:
                self.api_server.start()
            except Exception as e:
                logger.error(f"Error in API server: {e}")
                
        thread = threading.Thread(target=api_loop, daemon=True)
        thread.start()
        self.threads["api"] = thread
        
    def start_reporting_thread(self):
        """Start the reporting thread"""
        def reporting_loop():
            logger.info("Reporting thread started")
            while self.running:
                try:
                    # Generate a report once a day
                    self.report_generator.generate_summary_report()
                    # Sleep for 24 hours
                    for _ in range(24):
                        if not self.running:
                            break
                        time.sleep(3600)  # Sleep for an hour
                except Exception as e:
                    logger.error(f"Error in reporting loop: {e}")
                    time.sleep(3600)  # Sleep an hour before retrying
                    
        thread = threading.Thread(target=reporting_loop, daemon=True)
        thread.start()
        self.threads["reporting"] = thread
        
    def start(self):
        """Start all service components"""
        logger.info("Starting security service...")
        self.running = True
        
        self.start_monitoring_thread()
        self.start_api_thread()
        self.start_reporting_thread()
        
        logger.info("All service components started")
        
    def stop(self):
        """Stop all service components"""
        logger.info("Stopping security service...")
        self.running = False
        
        # Wait for threads to terminate
        for name, thread in self.threads.items():
            if thread.is_alive():
                logger.info(f"Waiting for {name} thread to terminate...")
                thread.join(timeout=5)
                
        logger.info("Security service stopped")
        
    def run(self):
        """Run the service"""
        try:
            self.start()
            # Keep the main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
            self.stop()
        except Exception as e:
            logger.error(f"Error in service runner: {e}")
            self.stop()
        finally:
            logger.info("Service runner terminated")
            
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security monitoring service runner")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon/service")
    args = parser.parse_args()
    
    service = SecurityServiceRunner()
    service.run()
