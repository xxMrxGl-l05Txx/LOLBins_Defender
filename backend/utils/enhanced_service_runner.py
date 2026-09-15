"""
Enhanced service runner with improved orchestration and monitoring
"""
import argparse
import logging
import platform
import signal
import sys
import threading
import time
import uuid
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, Any, List, Optional

if __package__ in (None, ''):
    # Allow running this file directly: python backend/utils/enhanced_service_runner.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import psutil
import schedule

from backend.core.config import ConfigManager
from backend.core.database import DatabaseManager
from backend.core.exceptions import SecurityMonitoringError
from backend.core.paths import LOG_DIR, system_disk_root
from backend.monitor.enhanced_monitor import EnhancedSecurityMonitor
from backend.detection.enhanced_detector import EnhancedSecurityDetector
from backend.alerting.enhanced_dispatcher import EnhancedAlertDispatcher
from backend.api.enhanced_api import EnhancedSecurityAPIServer
from backend.reporting.enhanced_report_generator import EnhancedSecurityReportGenerator

logger = logging.getLogger("EnhancedServiceRunner")

# Alerts tied to a specific process are de-duplicated per process by the
# monitor and detector; every other alert type is subject to the cooldown.
PROCESS_ALERT_TYPES = {'lolbin_detection', 'suspicious_network_activity', 'threat_pattern_detected', 'test_alert'}

class HealthMonitor:
    """Monitors the health of all system components"""

    def __init__(self):
        self.component_health = {}
        self.last_check = time.time()

    def check_component_health(self, component_name: str, component) -> bool:
        """Check if a component is healthy"""
        self.last_check = time.time()
        try:
            stats = component.get_performance_stats() if hasattr(component, 'get_performance_stats') else {}
            self.component_health[component_name] = {
                'status': 'healthy',
                'last_check': self.last_check,
                'stats': stats
            }
            return True
        except Exception as e:
            self.component_health[component_name] = {
                'status': 'unhealthy',
                'last_check': self.last_check,
                'error': str(e)
            }
            return False

    def get_overall_health(self) -> Dict[str, Any]:
        """Get overall system health status"""
        healthy_components = sum(1 for h in self.component_health.values() if h['status'] == 'healthy')
        total_components = len(self.component_health)

        return {
            'overall_status': 'healthy' if healthy_components == total_components else 'degraded',
            'healthy_components': healthy_components,
            'total_components': total_components,
            'components': self.component_health,
            'last_check': self.last_check
        }

class EnhancedSecurityServiceRunner:
    """Enhanced service runner with comprehensive monitoring and management"""

    def __init__(self, config_file: Optional[str] = None):
        self.config_manager = ConfigManager(config_file)
        self.db_manager = DatabaseManager()
        self.config = self.config_manager.get_config()
        self.hostname = platform.node()

        # Service state
        self.running = False
        self._stopped = False
        self._stop_event = threading.Event()
        self._scan_event = threading.Event()
        self._alerts_lock = threading.Lock()
        self._last_alert_by_type: Dict[str, float] = {}
        self.threads: Dict[str, threading.Thread] = {}
        self.health_monitor = HealthMonitor()
        self._scheduler = schedule.Scheduler()

        self.service_stats = {
            'start_time': None,
            'cycles_completed': 0,
            'total_alerts_processed': 0,
            'total_reports_generated': 0,
            'last_cycle_time': 0,
            'average_cycle_time': 0,
            'last_scan_at': None
        }

        self.metrics_history: List[Dict[str, Any]] = []
        self.recent_alerts: List[Dict[str, Any]] = []

        # Components
        self.monitor = EnhancedSecurityMonitor(self.config_manager, self.db_manager)
        self.detector = EnhancedSecurityDetector(self.config_manager, self.db_manager)
        self.alert_dispatcher = EnhancedAlertDispatcher(self.config_manager, self.db_manager)
        self.report_generator = EnhancedSecurityReportGenerator(self.db_manager)
        self.api_server = EnhancedSecurityAPIServer(
            self.config_manager,
            self.db_manager,
            report_generator=self.report_generator,
            scan_callback=self.request_scan,
            alert_sink=self.process_alerts,
            status_provider=self.get_service_status
        )

        logger.info("Enhanced security service runner initialized")

    def _signal_handler(self, sig, frame):
        """Handle termination signals gracefully"""
        logger.info(f"Received signal {sig}, initiating graceful shutdown...")
        self._stop_event.set()
        self._scan_event.set()

    def request_scan(self):
        """Wake the monitoring loop to run a cycle immediately"""
        logger.info("Immediate scan requested")
        self._scan_event.set()

    def process_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize, de-duplicate, store and dispatch alerts"""
        stored = []
        now = time.time()
        cooldown = self.config.alerting.alert_cooldown_seconds

        with self._alerts_lock:
            for alert in alerts:
                alert.setdefault('id', f"alert-{uuid.uuid4().hex}")
                alert.setdefault('timestamp', now)
                if not alert.get('system_name'):
                    alert['system_name'] = self.hostname
                alert['severity'] = str(alert.get('severity', 'MEDIUM')).upper()

                alert_type = alert.get('type', 'unknown')
                if alert_type not in PROCESS_ALERT_TYPES:
                    last = self._last_alert_by_type.get(alert_type)
                    if last is not None and now - last < cooldown:
                        logger.debug(f"Suppressed repeated {alert_type} alert (cooldown {cooldown}s)")
                        continue
                    self._last_alert_by_type[alert_type] = now

                if self.db_manager.insert_alert(alert):
                    stored.append(alert)

            if stored:
                self.recent_alerts.extend(stored)
                self.recent_alerts = self.recent_alerts[-500:]
                self.service_stats['total_alerts_processed'] += len(stored)

        if stored:
            logger.info(f"Stored {len(stored)} new alerts")
            self.alert_dispatcher.dispatch_bulk_alerts(stored)

        return stored

    def run_cycle(self):
        """Run one monitoring + detection cycle"""
        result = self.monitor.run_monitoring_cycle()

        metrics = result.get('metrics', {})
        if metrics:
            self.metrics_history.append(metrics)
            self.metrics_history = self.metrics_history[-1000:]

        alerts = list(result.get('alerts', []))

        try:
            alerts.extend(self.detector.detect_threats(
                self.metrics_history,
                self.recent_alerts,
                result.get('processes', [])
            ))
        except Exception as e:
            logger.error(f"Error in threat detection: {e}")

        self.process_alerts(alerts)
        self.service_stats['last_scan_at'] = time.time()

    def _monitoring_loop(self):
        """Main monitoring loop"""
        logger.info("Enhanced monitoring loop started")

        while not self._stop_event.is_set():
            cycle_start = time.time()

            try:
                self.run_cycle()

                cycle_time = time.time() - cycle_start
                self.service_stats['cycles_completed'] += 1
                self.service_stats['last_cycle_time'] = cycle_time
                self.service_stats['average_cycle_time'] = (
                    (time.time() - self.service_stats['start_time']) / self.service_stats['cycles_completed']
                )

                self.health_monitor.check_component_health('monitor', self.monitor)
                self.health_monitor.check_component_health('detector', self.detector)
                self.health_monitor.check_component_health('dispatcher', self.alert_dispatcher)

                logger.debug(f"Monitoring cycle completed in {cycle_time:.2f}s")
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                self.health_monitor.component_health['monitor'] = {
                    'status': 'unhealthy', 'last_check': time.time(), 'error': str(e)
                }

            # Sleep until the next interval, a scan request, or shutdown
            interval = self.config.monitoring.monitor_interval
            self._scan_event.wait(timeout=max(1, interval - (time.time() - cycle_start)))
            self._scan_event.clear()

    def _api_loop(self):
        """API server loop"""
        try:
            self.api_server.start()
        except Exception as e:
            logger.error(f"Error in API server: {e}")

    def _reporting_loop(self):
        """Automated reporting loop"""
        logger.info("Reporting loop started")

        self._scheduler.every().day.at("06:00").do(self._generate_report, days=1, label="daily")
        self._scheduler.every().monday.at("07:00").do(self._generate_report, days=7, label="weekly")
        self._scheduler.every().day.at("02:00").do(self._cleanup_old_data)

        while not self._stop_event.is_set():
            try:
                self._scheduler.run_pending()
            except Exception as e:
                logger.error(f"Error in reporting loop: {e}")
            self._stop_event.wait(60)

    def _generate_report(self, days: int, label: str):
        """Generate a scheduled security report"""
        logger.info(f"Generating {label} security report")
        report_path = self.report_generator.generate_summary_report(days=days)
        if report_path:
            self.service_stats['total_reports_generated'] += 1
            logger.info(f"{label.capitalize()} report generated: {report_path}")
        else:
            logger.warning(f"Failed to generate {label} report")

    def _cleanup_old_data(self):
        """Clean up old data based on retention policy"""
        try:
            if not self.config.enable_auto_cleanup:
                return

            retention_days = self.config.data_retention_days
            logger.info(f"Starting data cleanup (retention: {retention_days} days)")

            if not self.db_manager.cleanup_old_data(retention_days):
                logger.warning("Database cleanup failed")

            self.report_generator.cleanup_old_reports(retention_days)

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    def _health_check_loop(self):
        """Health monitoring loop"""
        logger.info("Health check loop started")

        while not self._stop_event.is_set():
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_percent = psutil.virtual_memory().percent
                disk_percent = psutil.disk_usage(system_disk_root()).percent

                if cpu_percent > 90:
                    logger.warning(f"High CPU usage detected: {cpu_percent:.1f}%")
                if memory_percent > 90:
                    logger.warning(f"High memory usage detected: {memory_percent:.1f}%")
                if disk_percent > 95:
                    logger.warning(f"High disk usage detected: {disk_percent:.1f}%")

                overall_health = self.health_monitor.get_overall_health()
                if overall_health['overall_status'] != 'healthy':
                    logger.warning(f"System health degraded: {overall_health}")

            except Exception as e:
                logger.error(f"Error in health check: {e}")

            self._stop_event.wait(300)

    def start(self):
        """Start all service components"""
        if self.running:
            logger.warning("Service is already running")
            return

        logger.info("Starting enhanced security monitoring service...")
        self.running = True
        self.service_stats['start_time'] = time.time()

        try:
            self.alert_dispatcher.start()
            self.monitor.start()

            for name, target in (
                ('monitoring', self._monitoring_loop),
                ('api', self._api_loop),
                ('reporting', self._reporting_loop),
                ('health', self._health_check_loop),
            ):
                thread = threading.Thread(target=target, daemon=True, name=f"{name.capitalize()}Thread")
                thread.start()
                self.threads[name] = thread

            api_config = self.config.api
            logger.info(f"All service components started - API at http://{api_config.host}:{api_config.port}/api/v1")

        except Exception as e:
            logger.error(f"Error starting service components: {e}")
            self.stop()
            raise SecurityMonitoringError(f"Failed to start service: {e}")

    def stop(self):
        """Stop all service components gracefully"""
        if not self.running or self._stopped:
            return
        self._stopped = True

        logger.info("Stopping enhanced security monitoring service...")
        self._stop_event.set()
        self._scan_event.set()

        try:
            self.alert_dispatcher.stop()
            self.monitor.stop()

            for name, thread in self.threads.items():
                # The Flask server thread is a daemon and exits with the process
                if name == 'api' or not thread.is_alive():
                    continue
                thread.join(timeout=10)
                if thread.is_alive():
                    logger.warning(f"{name} thread did not terminate gracefully")

            self._cleanup_old_data()

            uptime = time.time() - self.service_stats['start_time']
            logger.info(f"Service stopped. Uptime: {uptime:.1f}s, Cycles: {self.service_stats['cycles_completed']}")

        except Exception as e:
            logger.error(f"Error during service shutdown: {e}")

        self.running = False

    def get_service_status(self) -> Dict[str, Any]:
        """Get comprehensive service status"""
        start_time = self.service_stats['start_time']

        return {
            'running': self.running,
            'uptime_seconds': time.time() - start_time if start_time else 0,
            'statistics': dict(self.service_stats),
            'health': self.health_monitor.get_overall_health(),
            'threads': {name: thread.is_alive() for name, thread in self.threads.items()},
            'dispatcher': self.alert_dispatcher.get_statistics(),
            'configuration': {
                'monitoring_interval': self.config.monitoring.monitor_interval,
                'lolbin_detection_enabled': self.config.monitoring.enable_lolbin_detection,
                'data_retention_days': self.config.data_retention_days,
                'auto_cleanup_enabled': self.config.enable_auto_cleanup
            }
        }

    def run(self):
        """Run the service until interrupted"""
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._signal_handler)
            except (ValueError, OSError):
                pass  # Not in the main thread or unsupported on this platform

        try:
            self.start()
            while not self._stop_event.wait(1):
                pass
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
        except Exception as e:
            logger.error(f"Unexpected error in service runner: {e}")
        finally:
            self.stop()

def setup_logging(level: str):
    """Log to the console and a rotating file under data/logs"""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            RotatingFileHandler(LOG_DIR / 'security_monitoring.log', maxBytes=5 * 1024 * 1024,
                                backupCount=3, encoding='utf-8'),
            logging.StreamHandler()
        ],
        force=True
    )
    # Per-request access logs would drown out alerts while the dashboard polls
    logging.getLogger('werkzeug').setLevel(logging.WARNING)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Enhanced Security Monitoring Service")
    parser.add_argument("--config", default=None, help="Configuration file path (default: config.json in the project root)")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon/service")
    parser.add_argument("--log-level", default=None, choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Override the log_level from the configuration file")

    args = parser.parse_args()
    setup_logging(args.log_level or "INFO")

    try:
        service = EnhancedSecurityServiceRunner(args.config)
        if not args.log_level:
            logging.getLogger().setLevel(getattr(logging, service.config.log_level.upper(), logging.INFO))
        service.run()
    except Exception as e:
        logger.exception(f"Failed to start service: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
