"""
Custom exceptions for the security monitoring system
"""

class SecurityMonitoringError(Exception):
    """Base exception for security monitoring system"""
    pass

class ConfigurationError(SecurityMonitoringError):
    """Raised when there's a configuration error"""
    pass

class DatabaseError(SecurityMonitoringError):
    """Raised when there's a database error"""
    pass

class MonitoringError(SecurityMonitoringError):
    """Raised when there's a monitoring error"""
    pass

class AlertingError(SecurityMonitoringError):
    """Raised when there's an alerting error"""
    pass

class DetectionError(SecurityMonitoringError):
    """Raised when there's a detection error"""
    pass

class APIError(SecurityMonitoringError):
    """Raised when there's an API error"""
    pass

class ValidationError(SecurityMonitoringError):
    """Raised when data validation fails"""
    pass