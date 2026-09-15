"""
Configuration management for the security monitoring system
"""
import json
import logging
import threading
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict, fields

from .exceptions import ConfigurationError
from .paths import DEFAULT_CONFIG_FILE

logger = logging.getLogger(__name__)

@dataclass
class MonitoringConfig:
    """Configuration for monitoring parameters"""
    cpu_threshold: float = 80.0
    memory_threshold: float = 80.0
    disk_threshold: float = 90.0
    network_threshold: int = 1000000
    monitor_interval: int = 60
    enable_lolbin_detection: bool = True
    enable_process_monitoring: bool = True
    enable_file_monitoring: bool = True
    enable_registry_monitoring: bool = True

@dataclass
class AlertingConfig:
    """Configuration for alerting system"""
    enable_email_alerts: bool = False
    enable_sms_alerts: bool = False
    enable_desktop_notifications: bool = True
    enable_webhook_alerts: bool = False
    alert_cooldown_seconds: int = 300
    max_alerts_per_hour: int = 100
    email_smtp_server: Optional[str] = None
    email_smtp_port: int = 587
    email_username: Optional[str] = None
    email_password: Optional[str] = None
    webhook_url: Optional[str] = None

@dataclass
class APIConfig:
    """Configuration for API server"""
    host: str = "127.0.0.1"
    port: int = 5000
    enable_cors: bool = True
    enable_rate_limiting: bool = True
    rate_limit_per_minute: int = 100
    enable_authentication: bool = False
    api_key: Optional[str] = None

@dataclass
class SystemConfig:
    """Main system configuration"""
    monitoring: MonitoringConfig
    alerting: AlertingConfig
    api: APIConfig
    log_level: str = "INFO"
    data_retention_days: int = 30
    enable_auto_cleanup: bool = True
    backup_enabled: bool = True
    backup_interval_hours: int = 24

# Fields that may be changed at runtime through the API, with allowed ranges.
# Credentials, webhook targets and API settings are only editable in the file.
EDITABLE_FIELDS = {
    'monitoring': {
        'cpu_threshold': (1, 100),
        'memory_threshold': (1, 100),
        'disk_threshold': (1, 100),
        'network_threshold': (0, None),
        'monitor_interval': (5, 86400),
        'enable_lolbin_detection': None,
        'enable_process_monitoring': None,
        'enable_file_monitoring': None,
        'enable_registry_monitoring': None,
    },
    'alerting': {
        'enable_email_alerts': None,
        'enable_desktop_notifications': None,
        'enable_webhook_alerts': None,
        'alert_cooldown_seconds': (0, 86400),
        'max_alerts_per_hour': (1, 100000),
    },
    None: {
        'log_level': None,
        'data_retention_days': (1, 3650),
        'enable_auto_cleanup': None,
    },
}

SECRET_FIELDS = {'email_password', 'api_key'}
LOG_LEVELS = {'DEBUG', 'INFO', 'WARNING', 'ERROR'}


def _known_fields(cls, data: Dict[str, Any]) -> Dict[str, Any]:
    """Drop keys the dataclass does not define so stale config files still load"""
    names = {f.name for f in fields(cls)}
    unknown = set(data) - names
    if unknown:
        logger.warning(f"Ignoring unknown {cls.__name__} keys: {sorted(unknown)}")
    return {k: v for k, v in data.items() if k in names}


def _coerce(value: Any, current: Any, name: str, bounds) -> Any:
    """Convert an incoming value to the type of the current value and range-check it"""
    try:
        if isinstance(current, bool):
            if isinstance(value, str):
                if value.lower() not in ('true', 'false', '1', '0'):
                    raise ValueError
                value = value.lower() in ('true', '1')
            else:
                value = bool(value)
        elif isinstance(current, int):
            if isinstance(value, bool) or float(value) != int(float(value)):
                raise ValueError
            value = int(float(value))
        elif isinstance(current, float):
            if isinstance(value, bool):
                raise ValueError
            value = float(value)
        elif isinstance(current, str):
            value = str(value)
    except (TypeError, ValueError):
        raise ConfigurationError(f"Invalid value for {name}: {value!r}")

    if bounds and isinstance(value, (int, float)) and not isinstance(value, bool):
        low, high = bounds
        if (low is not None and value < low) or (high is not None and value > high):
            raise ConfigurationError(f"{name} must be between {low} and {high if high is not None else 'unbounded'}")

    return value


class ConfigManager:
    """Manages system configuration"""

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = Path(config_file) if config_file else DEFAULT_CONFIG_FILE
        self.lock = threading.RLock()
        self.config = self._load_config()

    def _load_config(self) -> SystemConfig:
        """Load configuration from file or create default"""
        if not self.config_file.exists():
            return self._create_default_config()

        try:
            # utf-8-sig tolerates the byte-order mark some Windows editors add
            with open(self.config_file, 'r', encoding='utf-8-sig') as f:
                data = json.load(f)

            return SystemConfig(
                monitoring=MonitoringConfig(**_known_fields(MonitoringConfig, data.get('monitoring', {}))),
                alerting=AlertingConfig(**_known_fields(AlertingConfig, data.get('alerting', {}))),
                api=APIConfig(**_known_fields(APIConfig, data.get('api', {}))),
                log_level=data.get('log_level', 'INFO'),
                data_retention_days=data.get('data_retention_days', 30),
                enable_auto_cleanup=data.get('enable_auto_cleanup', True),
                backup_enabled=data.get('backup_enabled', True),
                backup_interval_hours=data.get('backup_interval_hours', 24)
            )
        except Exception as e:
            # Keep the broken file untouched so the user can fix it
            logger.error(f"Error loading config from {self.config_file}, using defaults: {e}")
            return SystemConfig(monitoring=MonitoringConfig(), alerting=AlertingConfig(), api=APIConfig())

    def _create_default_config(self) -> SystemConfig:
        """Create default configuration"""
        config = SystemConfig(
            monitoring=MonitoringConfig(),
            alerting=AlertingConfig(),
            api=APIConfig()
        )
        self.save_config(config)
        return config

    def to_dict(self, config: SystemConfig = None, redact: bool = False) -> Dict[str, Any]:
        """Serialize configuration, optionally hiding secrets"""
        config = config or self.config
        config_dict = {
            'monitoring': asdict(config.monitoring),
            'alerting': asdict(config.alerting),
            'api': asdict(config.api),
            'log_level': config.log_level,
            'data_retention_days': config.data_retention_days,
            'enable_auto_cleanup': config.enable_auto_cleanup,
            'backup_enabled': config.backup_enabled,
            'backup_interval_hours': config.backup_interval_hours
        }
        if redact:
            for section in ('alerting', 'api'):
                for key in SECRET_FIELDS:
                    if key in config_dict[section]:
                        config_dict[section][key] = '********' if config_dict[section][key] else None
        return config_dict

    def save_config(self, config: SystemConfig = None) -> bool:
        """Save configuration to file"""
        if config is None:
            config = self.config

        try:
            with self.lock:
                with open(self.config_file, 'w', encoding='utf-8') as f:
                    json.dump(self.to_dict(config), f, indent=2)
                self.config = config
            logger.info("Configuration saved successfully")
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False

    def get_config(self) -> SystemConfig:
        """Get current configuration"""
        return self.config

    def update_config(self, updates: Dict[str, Any] = None, **kwargs) -> bool:
        """
        Update configuration in place so running components see the change.

        Accepts nested sections ({"monitoring": {"cpu_threshold": 90}}) or flat
        field names. Raises ConfigurationError for unknown, read-only or
        invalid values; nothing is applied unless every value is valid.
        """
        updates = {**(updates or {}), **kwargs}
        changes = []  # (target object, field, value)

        with self.lock:
            for key, value in updates.items():
                if key in ('monitoring', 'alerting', 'api') and isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        changes.append(self._validate_change(key, sub_key, sub_value))
                else:
                    changes.append(self._validate_change(self._section_for(key), key, value))

            for target, name, value in changes:
                setattr(target, name, value)

            return self.save_config()

    def _section_for(self, key: str) -> Optional[str]:
        """Find which section a flat key belongs to"""
        if key in EDITABLE_FIELDS[None]:
            return None
        for section in ('monitoring', 'alerting'):
            if key in EDITABLE_FIELDS[section]:
                return section
        raise ConfigurationError(f"Unknown or read-only setting: {key}")

    def _validate_change(self, section: Optional[str], key: str, value: Any):
        allowed = EDITABLE_FIELDS.get(section, {})
        label = f"{section}.{key}" if section else key
        if key not in allowed:
            raise ConfigurationError(f"Unknown or read-only setting: {label}")

        target = getattr(self.config, section) if section else self.config
        coerced = _coerce(value, getattr(target, key), label, allowed[key])

        if key == 'log_level':
            coerced = coerced.upper()
            if coerced not in LOG_LEVELS:
                raise ConfigurationError(f"log_level must be one of {sorted(LOG_LEVELS)}")

        return target, key, coerced
