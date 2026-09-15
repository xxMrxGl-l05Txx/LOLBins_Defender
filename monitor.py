import logging
import datetime
from enum import Enum

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class LOLBinMonitor:
    def __init__(self, log_file="lolbin_alerts.log"):
        # Configure logging
        self.logger = logging.getLogger("LOLBinMonitor")
        self.logger.setLevel(logging.INFO)
        
        # Create file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Create formatter and add it to the handlers
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def log_alert(self, binary_name, command, severity, process_id=None, user=None):
        """
        Log a LOLBin alert with timestamp and severity level
        """
        timestamp = datetime.datetime.now().isoformat()
        
        # Create alert message
        alert_message = f"LOLBin Alert: {binary_name} detected with potential malicious use"
        details = {
            "binary": binary_name,
            "command": command,
            "severity": severity.value,
            "timestamp": timestamp
        }
        
        if process_id:
            details["process_id"] = process_id
        
        if user:
            details["user"] = user
        
        # Log based on severity
        if severity == Severity.CRITICAL:
            self.logger.critical(f"{alert_message} - {details}")
        elif severity == Severity.HIGH:
            self.logger.error(f"{alert_message} - {details}")
        elif severity == Severity.MEDIUM:
            self.logger.warning(f"{alert_message} - {details}")
        else:  # LOW
            self.logger.info(f"{alert_message} - {details}")
        
        return details
