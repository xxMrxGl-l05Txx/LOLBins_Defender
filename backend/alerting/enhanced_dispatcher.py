"""
Enhanced alert dispatcher with multiple notification channels and rate limiting
"""
import html
import logging
import os
import platform
import smtplib
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from queue import Queue, Empty
from typing import Dict, List, Any, Optional

import requests

from ..core.config import ConfigManager, AlertingConfig
from ..core.database import DatabaseManager

logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiter for alerts to prevent spam"""

    def __init__(self, max_alerts_per_hour: int = 100):
        self.max_alerts_per_hour = max_alerts_per_hour
        self.alert_timestamps = deque()
        self.lock = threading.Lock()

    def can_send_alert(self) -> bool:
        """Check if we can send an alert based on rate limits"""
        with self.lock:
            now = time.time()
            hour_ago = now - 3600

            while self.alert_timestamps and self.alert_timestamps[0] < hour_ago:
                self.alert_timestamps.popleft()

            if len(self.alert_timestamps) < self.max_alerts_per_hour:
                self.alert_timestamps.append(now)
                return True

            return False

class AlertCooldown:
    """Manages cooldown periods for similar alerts"""

    def __init__(self, cooldown_seconds: int = 300):
        self.cooldown_seconds = cooldown_seconds
        self.last_alerts = {}
        self.lock = threading.Lock()

    def can_send_alert(self, key: str) -> bool:
        """Check if we can send an alert based on cooldown"""
        with self.lock:
            now = time.time()
            last = self.last_alerts.get(key)
            if last is not None and now - last < self.cooldown_seconds:
                return False

            self.last_alerts[key] = now
            return True

def _format_timestamp(value: Any) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')
    return str(value or 'N/A')

class EmailNotifier:
    """Email notification handler"""

    def __init__(self, config: AlertingConfig):
        self.config = config

    @property
    def enabled(self) -> bool:
        c = self.config
        return bool(c.enable_email_alerts and c.email_smtp_server and c.email_username and c.email_password)

    def send_notification(self, alert: Dict[str, Any]) -> bool:
        """Send email notification"""
        if not self.enabled:
            return False

        try:
            msg = MIMEMultipart()
            msg['From'] = self.config.email_username
            msg['To'] = self.config.email_username  # Send to self for now
            msg['Subject'] = f"Security Alert [{alert.get('severity', 'UNKNOWN')}]: {alert.get('type', 'Unknown')}"
            msg.attach(MIMEText(self._create_email_body(alert), 'html'))

            with smtplib.SMTP(self.config.email_smtp_server, self.config.email_smtp_port, timeout=30) as server:
                server.starttls()
                server.login(self.config.email_username, self.config.email_password)
                server.send_message(msg)

            logger.info(f"Email alert sent for {alert.get('id')}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False

    def _create_email_body(self, alert: Dict[str, Any]) -> str:
        """Create HTML email body; alert fields are escaped since command lines are attacker-controlled"""
        severity = str(alert.get('severity', 'UNKNOWN'))
        severity_color = {
            'CRITICAL': '#FF0000',
            'HIGH': '#FF6600',
            'MEDIUM': '#FFAA00',
            'LOW': '#00AA00'
        }.get(severity, '#666666')

        def field(name: str) -> str:
            return html.escape(str(alert.get(name) or 'N/A'))

        return f"""
        <html>
        <body>
            <h2 style="color: {severity_color};">Security Alert - {html.escape(severity)}</h2>
            <table border="1" cellpadding="5" cellspacing="0">
                <tr><td><strong>Alert ID:</strong></td><td>{field('id')}</td></tr>
                <tr><td><strong>Type:</strong></td><td>{field('type')}</td></tr>
                <tr><td><strong>Severity:</strong></td><td style="color: {severity_color};">{html.escape(severity)}</td></tr>
                <tr><td><strong>Timestamp:</strong></td><td>{html.escape(_format_timestamp(alert.get('timestamp')))}</td></tr>
                <tr><td><strong>System:</strong></td><td>{field('system_name')}</td></tr>
                <tr><td><strong>Details:</strong></td><td>{field('details')}</td></tr>
                <tr><td><strong>Binary:</strong></td><td>{field('binary')}</td></tr>
                <tr><td><strong>Command:</strong></td><td><code>{field('command')}</code></td></tr>
            </table>
            <p><strong>Recommended Action:</strong> Investigate this alert immediately and take appropriate mitigation steps.</p>
        </body>
        </html>
        """

class WebhookNotifier:
    """Webhook notification handler"""

    def __init__(self, config: AlertingConfig):
        self.config = config

    @property
    def enabled(self) -> bool:
        return bool(self.config.enable_webhook_alerts and self.config.webhook_url)

    def send_notification(self, alert: Dict[str, Any]) -> bool:
        """Send webhook notification"""
        if not self.enabled:
            return False

        try:
            payload = {
                'alert_id': alert.get('id'),
                'type': alert.get('type'),
                'severity': alert.get('severity'),
                'timestamp': alert.get('timestamp'),
                'details': alert.get('details'),
                'system': alert.get('system_name'),
                'binary': alert.get('binary'),
                'command': alert.get('command'),
                'mitre_id': alert.get('mitre_id')
            }

            response = requests.post(self.config.webhook_url, json=payload, timeout=10)

            if response.ok:
                logger.info(f"Webhook alert sent for {alert.get('id')}")
                return True

            logger.error(f"Webhook failed with status {response.status_code}")
            return False

        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False

# Shows a non-blocking tray balloon. Title and text arrive via environment
# variables so alert content can never be interpreted as PowerShell code.
WINDOWS_BALLOON_SCRIPT = (
    "Add-Type -AssemblyName System.Windows.Forms, System.Drawing; "
    "$icon = New-Object System.Windows.Forms.NotifyIcon; "
    "$icon.Icon = [System.Drawing.SystemIcons]::Warning; "
    "$icon.BalloonTipIcon = 'Warning'; "
    "$icon.BalloonTipTitle = $env:SECMON_TITLE; "
    "$icon.BalloonTipText = $env:SECMON_MESSAGE; "
    "$icon.Visible = $true; "
    "$icon.ShowBalloonTip(10000); "
    "Start-Sleep -Seconds 10; "
    "$icon.Dispose()"
)

class DesktopNotifier:
    """Desktop notification handler"""

    def __init__(self, config: AlertingConfig):
        self.config = config

    @property
    def enabled(self) -> bool:
        return bool(self.config.enable_desktop_notifications)

    def send_notification(self, alert: Dict[str, Any]) -> bool:
        """Send desktop notification without blocking the dispatcher"""
        if not self.enabled:
            return False

        title = f"Security Alert - {alert.get('severity', 'UNKNOWN')}"
        subject = alert.get('binary') or str(alert.get('type', 'alert')).replace('_', ' ')
        message = f"{subject}: {alert.get('details', '')}".strip()

        try:
            system = platform.system()
            if system == "Windows":
                return self._send_windows_notification(title, message)
            if system == "Darwin":
                return self._spawn([
                    'osascript',
                    '-e', 'on run argv',
                    '-e', 'display notification (item 2 of argv) with title (item 1 of argv)',
                    '-e', 'end run',
                    title, message
                ])
            if system == "Linux":
                return self._spawn(['notify-send', title, message])
            return False

        except Exception as e:
            logger.error(f"Failed to send desktop notification: {e}")
            return False

    @staticmethod
    def _powershell_path() -> str:
        # Services and restricted shells may not have System32 on PATH
        candidate = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                                 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
        return candidate if os.path.exists(candidate) else 'powershell'

    def _send_windows_notification(self, title: str, message: str) -> bool:
        env = dict(os.environ, SECMON_TITLE=title[:63], SECMON_MESSAGE=(message[:250] or ' '))
        return self._spawn(
            [self._powershell_path(), '-NoLogo', '-NonInteractive', '-Command', WINDOWS_BALLOON_SCRIPT],
            env=env,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )

    @staticmethod
    def _spawn(args: List[str], env: Optional[Dict[str, str]] = None, creationflags: int = 0) -> bool:
        try:
            subprocess.Popen(
                args,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags
            )
            return True
        except OSError as e:
            logger.warning(f"Desktop notification command unavailable ({args[0]}): {e}")
            return False

class EnhancedAlertDispatcher:
    """Enhanced alert dispatcher with multiple channels and intelligent routing"""

    def __init__(self, config_manager: ConfigManager, db_manager: DatabaseManager):
        self.config_manager = config_manager
        self.db_manager = db_manager
        # Keep a reference to the live config object so API changes apply immediately
        self.config = config_manager.get_config().alerting

        self.rate_limiter = RateLimiter(self.config.max_alerts_per_hour)
        self.cooldown_manager = AlertCooldown(self.config.alert_cooldown_seconds)

        # Every channel is created; each checks its own enabled flag at send time
        self.notifiers = {
            'desktop': DesktopNotifier(self.config),
            'email': EmailNotifier(self.config),
            'webhook': WebhookNotifier(self.config),
        }

        self.alert_queue = Queue()
        self.processing_thread = None
        self.running = False

        self.stats = {
            'total_alerts': 0,
            'alerts_sent': 0,
            'alerts_dropped': 0,
            'alerts_by_severity': defaultdict(int),
            'alerts_by_type': defaultdict(int),
            'notifier_stats': defaultdict(lambda: {'sent': 0, 'failed': 0})
        }

        logger.info(f"Enhanced alert dispatcher initialized (enabled channels: {self._enabled_channels()})")

    def _enabled_channels(self) -> List[str]:
        return [name for name, notifier in self.notifiers.items() if notifier.enabled]

    def start(self):
        """Start the alert processing thread"""
        if self.running:
            return

        self.running = True
        self.processing_thread = threading.Thread(target=self._process_alerts, daemon=True, name="AlertDispatcher")
        self.processing_thread.start()
        logger.info("Alert dispatcher started")

    def stop(self):
        """Stop the alert processing thread"""
        self.running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        logger.info("Alert dispatcher stopped")

    def dispatch_alert(self, alert: Dict[str, Any]) -> bool:
        """Queue an alert for delivery through the appropriate channels"""
        try:
            if not self._validate_alert(alert):
                logger.warning(f"Invalid alert format: {alert}")
                return False

            self.alert_queue.put(alert)
            self.stats['total_alerts'] += 1
            self.stats['alerts_by_severity'][alert.get('severity', 'UNKNOWN')] += 1
            self.stats['alerts_by_type'][alert.get('type', 'unknown')] += 1

            return True

        except Exception as e:
            logger.error(f"Error dispatching alert: {e}")
            return False

    def _process_alerts(self):
        """Process alerts from the queue"""
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1)
                self._process_single_alert(alert)
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing alert: {e}")

    def _process_single_alert(self, alert: Dict[str, Any]):
        """Process a single alert"""
        try:
            alert_id = alert.get('id', 'unknown')
            alert_type = alert.get('type', 'unknown')
            severity = alert.get('severity', 'UNKNOWN')

            notifiers_to_use = self._select_notifiers(severity)
            if not notifiers_to_use:
                return

            # Pick up limit changes made through the API
            self.rate_limiter.max_alerts_per_hour = self.config.max_alerts_per_hour
            self.cooldown_manager.cooldown_seconds = self.config.alert_cooldown_seconds

            cooldown_key = f"{alert_type}:{alert.get('binary') or ''}"
            if alert_type != 'test_alert' and not self.cooldown_manager.can_send_alert(cooldown_key):
                logger.debug(f"Alert {alert_id} notification suppressed by cooldown")
                self.stats['alerts_dropped'] += 1
                return

            if not self.rate_limiter.can_send_alert():
                logger.warning(f"Alert {alert_id} notification dropped due to rate limiting")
                self.stats['alerts_dropped'] += 1
                return

            success_count = 0
            for notifier_name in notifiers_to_use:
                try:
                    if self.notifiers[notifier_name].send_notification(alert):
                        success_count += 1
                        self.stats['notifier_stats'][notifier_name]['sent'] += 1
                    else:
                        self.stats['notifier_stats'][notifier_name]['failed'] += 1
                except Exception as e:
                    logger.error(f"Error sending alert via {notifier_name}: {e}")
                    self.stats['notifier_stats'][notifier_name]['failed'] += 1

            if success_count > 0:
                self.stats['alerts_sent'] += 1
                logger.info(f"Alert {alert_id} sent via {success_count} notifiers")
            else:
                logger.warning(f"Alert {alert_id} failed to send via any notifier")
                self.stats['alerts_dropped'] += 1

        except Exception as e:
            logger.error(f"Error processing alert {alert.get('id', 'unknown')}: {e}")

    def _select_notifiers(self, severity: str) -> List[str]:
        """Select appropriate notifiers based on alert severity"""
        notifiers = []

        if self.notifiers['desktop'].enabled:
            notifiers.append('desktop')

        # Email only for HIGH and CRITICAL alerts
        if severity in ('HIGH', 'CRITICAL') and self.notifiers['email'].enabled:
            notifiers.append('email')

        if self.notifiers['webhook'].enabled:
            notifiers.append('webhook')

        return notifiers

    def _validate_alert(self, alert: Dict[str, Any]) -> bool:
        """Validate alert format"""
        required_fields = ['id', 'timestamp', 'type', 'severity']
        return all(field in alert for field in required_fields)

    def get_statistics(self) -> Dict[str, Any]:
        """Get dispatcher statistics"""
        return {
            'stats': {
                **{k: v for k, v in self.stats.items() if not isinstance(v, defaultdict)},
                'alerts_by_severity': dict(self.stats['alerts_by_severity']),
                'alerts_by_type': dict(self.stats['alerts_by_type']),
                'notifier_stats': dict(self.stats['notifier_stats']),
            },
            'queue_size': self.alert_queue.qsize(),
            'running': self.running,
            'notifiers_enabled': self._enabled_channels()
        }

    def dispatch_bulk_alerts(self, alerts: List[Dict[str, Any]]) -> List[bool]:
        """Dispatch multiple alerts"""
        return [self.dispatch_alert(alert) for alert in alerts]
