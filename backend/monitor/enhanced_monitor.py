"""
Enhanced security monitoring with comprehensive system analysis
"""
import ipaddress
import os
import time
import uuid
import logging
import platform
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Any, Set, Tuple

import psutil

from ..core.config import ConfigManager
from ..core.database import DatabaseManager
from ..core.exceptions import MonitoringError
from ..core.paths import system_disk_root
from ..detection.lolbin_rules import load_rules, match_lolbin, normalize_binary

logger = logging.getLogger(__name__)

# Ports commonly used by reverse shells and C2 frameworks
SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 9999}

# Binaries that should rarely talk to the internet directly
SHELL_BINARIES = {'cmd', 'powershell', 'pwsh', 'certutil', 'bitsadmin', 'mshta', 'rundll32', 'regsvr32'}

@dataclass
class ProcessInfo:
    """Information about a running process"""
    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: List[str]
    username: str
    cpu_percent: float
    memory_percent: float
    create_time: float
    connections: List[Dict[str, Any]] = field(default_factory=list)

class EnhancedSecurityMonitor:
    """Enhanced security monitor with comprehensive system analysis"""

    def __init__(self, config_manager: ConfigManager, db_manager: DatabaseManager,
                 establish_baseline: bool = True):
        self.config_manager = config_manager
        self.db_manager = db_manager
        self.config = config_manager.get_config()

        # Load LOLBins rules
        self.lolbins_rules = load_rules()

        # Monitoring state
        self.running = False
        self.last_metrics = {}
        self.baseline_metrics = {}
        self.hostname = platform.node()
        self._own_pid = os.getpid()

        # Processes already reported, keyed by (pid, create_time, rule) so a
        # long-running process is reported once rather than every cycle
        self._reported_lolbins: Set[Tuple[int, float, str]] = set()
        self._reported_network: Set[Tuple[int, float]] = set()

        # Performance tracking
        self.performance_history = []

        self.system_info = self._collect_system_info()

        if establish_baseline:
            self._establish_baseline()

        logger.info(f"Enhanced security monitor initialized with {len(self.lolbins_rules)} LOLBin rules")

    def _establish_baseline(self, samples: int = 5):
        """Establish baseline system metrics"""
        try:
            baseline_samples = [m for m in (self._collect_basic_metrics(cpu_interval=0.5) for _ in range(samples)) if m]
            if not baseline_samples:
                return

            keys = ('cpu_percent', 'memory_percent', 'disk_percent', 'process_count', 'network_connections')
            self.baseline_metrics = {
                key: sum(m[key] for m in baseline_samples) / len(baseline_samples) for key in keys
            }

            logger.info(f"Baseline established: {self.baseline_metrics}")
        except Exception as e:
            logger.error(f"Error establishing baseline: {e}")
            self.baseline_metrics = {}

    def _collect_basic_metrics(self, cpu_interval: float = 1.0) -> Dict[str, Any]:
        """Collect basic system metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=cpu_interval)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage(system_disk_root())

            network_io = psutil.net_io_counters()
            bytes_sent = network_io.bytes_sent if network_io else 0
            bytes_recv = network_io.bytes_recv if network_io else 0

            try:
                network_connections = len(psutil.net_connections(kind='inet'))
            except (psutil.AccessDenied, OSError):
                network_connections = 0

            return {
                'timestamp': time.time(),
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': disk.percent,
                'network_bytes_sent': bytes_sent,
                'network_bytes_recv': bytes_recv,
                'network_bytes': bytes_sent + bytes_recv,
                'network_connections': network_connections,
                'active_connections': network_connections,
                'process_count': len(psutil.pids()),
            }
        except Exception as e:
            logger.error(f"Error collecting basic metrics: {e}")
            return {}

    def _collect_process_information(self) -> List[ProcessInfo]:
        """Collect detailed process information"""
        processes = []

        # One system-wide connection query is far cheaper than one per process
        connections_by_pid: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.pid:
                    connections_by_pid[conn.pid].append({
                        'local_address': conn.laddr.ip if conn.laddr else '',
                        'local_port': conn.laddr.port if conn.laddr else 0,
                        'remote_address': conn.raddr.ip if conn.raddr else '',
                        'remote_port': conn.raddr.port if conn.raddr else 0,
                        'status': conn.status
                    })
        except (psutil.AccessDenied, OSError) as e:
            logger.debug(f"Could not enumerate network connections: {e}")

        attrs = ['pid', 'ppid', 'name', 'exe', 'cmdline', 'username',
                 'cpu_percent', 'memory_percent', 'create_time']
        try:
            for proc in psutil.process_iter(attrs):
                try:
                    info = proc.info
                    pid = info['pid']

                    # Skip this service and helpers it launched (e.g. notification popups)
                    if pid == self._own_pid or info.get('ppid') == self._own_pid:
                        continue

                    processes.append(ProcessInfo(
                        pid=pid,
                        ppid=info.get('ppid') or 0,
                        name=info.get('name') or '',
                        exe=info.get('exe') or '',
                        cmdline=info.get('cmdline') or [],
                        username=info.get('username') or '',
                        cpu_percent=info.get('cpu_percent') or 0,
                        memory_percent=info.get('memory_percent') or 0,
                        create_time=info.get('create_time') or 0,
                        connections=connections_by_pid.get(pid, [])
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            logger.error(f"Error collecting process information: {e}")

        return processes

    def _analyze_lolbins_activity(self, processes: List[ProcessInfo]) -> List[Dict[str, Any]]:
        """Analyze processes for LOLBins activity"""
        alerts = []
        active_keys = set()

        for process in processes:
            command = ' '.join(process.cmdline)
            match = match_lolbin(process.name or process.exe, command, self.lolbins_rules)
            if not match:
                continue

            rule = match['rule']
            key = (process.pid, process.create_time, normalize_binary(rule.get('binary', '')))
            active_keys.add(key)
            if key in self._reported_lolbins:
                continue
            self._reported_lolbins.add(key)

            alerts.append({
                'id': f"lolbin-{uuid.uuid4().hex}",
                'timestamp': time.time(),
                'type': 'lolbin_detection',
                'severity': match['severity'],
                'binary': process.name,
                'command': command,
                'process_id': process.pid,
                'user_name': process.username,
                'system_name': self.hostname,
                'mitre_id': rule.get('mitre_attack_id'),
                'mitre_link': rule.get('mitre_link'),
                'details': f"Suspicious {rule.get('binary')} execution detected: {rule.get('description', '')}",
                'metadata': {
                    'rule': rule,
                    'patterns_matched': match['patterns'],
                    'process_info': asdict(process)
                }
            })

        # Forget processes that have exited so a reused PID is reported again
        self._reported_lolbins &= active_keys
        return alerts

    def _analyze_anomalies(self, current_metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze current metrics for deviations from the startup baseline"""
        alerts = []

        if not self.baseline_metrics:
            return alerts

        try:
            cpu_deviation = abs(current_metrics['cpu_percent'] - self.baseline_metrics['cpu_percent'])
            if cpu_deviation > 30:  # 30% deviation from baseline
                alerts.append({
                    'id': f"anomaly-cpu-{uuid.uuid4().hex}",
                    'timestamp': time.time(),
                    'type': 'cpu_anomaly',
                    'severity': 'HIGH' if cpu_deviation > 50 else 'MEDIUM',
                    'system_name': self.hostname,
                    'details': f"CPU usage anomaly detected: {current_metrics['cpu_percent']:.1f}% (baseline: {self.baseline_metrics['cpu_percent']:.1f}%)",
                    'metadata': {
                        'current_value': current_metrics['cpu_percent'],
                        'baseline_value': self.baseline_metrics['cpu_percent'],
                        'deviation': cpu_deviation
                    }
                })

            memory_deviation = abs(current_metrics['memory_percent'] - self.baseline_metrics['memory_percent'])
            if memory_deviation > 25:  # 25% deviation from baseline
                alerts.append({
                    'id': f"anomaly-memory-{uuid.uuid4().hex}",
                    'timestamp': time.time(),
                    'type': 'memory_anomaly',
                    'severity': 'HIGH' if memory_deviation > 40 else 'MEDIUM',
                    'system_name': self.hostname,
                    'details': f"Memory usage anomaly detected: {current_metrics['memory_percent']:.1f}% (baseline: {self.baseline_metrics['memory_percent']:.1f}%)",
                    'metadata': {
                        'current_value': current_metrics['memory_percent'],
                        'baseline_value': self.baseline_metrics['memory_percent'],
                        'deviation': memory_deviation
                    }
                })

            process_deviation = abs(current_metrics['process_count'] - self.baseline_metrics['process_count'])
            if process_deviation > 50:  # 50 process deviation
                alerts.append({
                    'id': f"anomaly-processes-{uuid.uuid4().hex}",
                    'timestamp': time.time(),
                    'type': 'process_anomaly',
                    'severity': 'MEDIUM',
                    'system_name': self.hostname,
                    'details': f"Process count anomaly detected: {current_metrics['process_count']} (baseline: {self.baseline_metrics['process_count']:.0f})",
                    'metadata': {
                        'current_value': current_metrics['process_count'],
                        'baseline_value': self.baseline_metrics['process_count'],
                        'deviation': process_deviation
                    }
                })

        except Exception as e:
            logger.error(f"Error analyzing anomalies: {e}")

        return alerts

    def _check_thresholds(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if metrics exceed configured thresholds"""
        alerts = []
        config = self.config.monitoring

        checks = [
            ('cpu_percent', 'high_cpu', 'CPU', config.cpu_threshold, 95),
            ('memory_percent', 'high_memory', 'Memory', config.memory_threshold, 95),
            ('disk_percent', 'high_disk', 'Disk', config.disk_threshold, 98),
        ]

        for key, alert_type, label, threshold, high_above in checks:
            value = metrics.get(key, 0)
            if value > threshold:
                alerts.append({
                    'id': f"threshold-{alert_type}-{uuid.uuid4().hex}",
                    'timestamp': time.time(),
                    'type': alert_type,
                    'severity': 'HIGH' if value > high_above else 'MEDIUM',
                    'system_name': self.hostname,
                    'details': f"{label} usage above threshold: {value:.1f}% (threshold: {threshold}%)",
                    'metadata': {'value': value, 'threshold': threshold}
                })

        return alerts

    def _analyze_network_activity(self, processes: List[ProcessInfo]) -> List[Dict[str, Any]]:
        """Analyze network activity for suspicious patterns"""
        alerts = []
        active_keys = set()

        try:
            for process in processes:
                is_shell = normalize_binary(process.name) in SHELL_BINARIES
                suspicious_connections = []

                for conn in process.connections:
                    remote_ip = conn.get('remote_address', '')
                    if not remote_ip or self._is_loopback(remote_ip):
                        continue

                    if conn.get('remote_port') in SUSPICIOUS_PORTS:
                        suspicious_connections.append(conn)
                    elif is_shell and not self._is_private_ip(remote_ip):
                        suspicious_connections.append(conn)

                if not suspicious_connections:
                    continue

                key = (process.pid, process.create_time)
                active_keys.add(key)
                if key in self._reported_network:
                    continue
                self._reported_network.add(key)

                alerts.append({
                    'id': f"network-{uuid.uuid4().hex}",
                    'timestamp': time.time(),
                    'type': 'suspicious_network_activity',
                    'severity': 'HIGH',
                    'binary': process.name,
                    'command': ' '.join(process.cmdline),
                    'process_id': process.pid,
                    'user_name': process.username,
                    'system_name': self.hostname,
                    'details': f"Suspicious network activity detected from {process.name} (PID: {process.pid})",
                    'metadata': {
                        'process_info': asdict(process),
                        'suspicious_connections': suspicious_connections
                    }
                })

        except Exception as e:
            logger.error(f"Error analyzing network activity: {e}")

        self._reported_network &= active_keys
        return alerts

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP address is in private range"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def _is_loopback(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_loopback
        except ValueError:
            return False

    def _collect_system_info(self) -> Dict[str, Any]:
        """Collect comprehensive system information"""
        try:
            boot_time = psutil.boot_time()

            return {
                'hostname': self.hostname,
                'os_name': platform.system(),
                'os_version': platform.version(),
                'cpu_count': psutil.cpu_count(),
                'total_memory': psutil.virtual_memory().total,
                'disk_size': psutil.disk_usage(system_disk_root()).total,
                'last_boot': boot_time,
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'python_version': platform.python_version()
            }
        except Exception as e:
            logger.error(f"Error collecting system info: {e}")
            return {}

    def run_monitoring_cycle(self) -> Dict[str, Any]:
        """
        Run a complete monitoring cycle. Metrics are stored here; alerts are
        returned to the caller, which de-duplicates, stores and dispatches them.
        """
        cycle_start = time.time()

        try:
            logger.debug("Starting enhanced monitoring cycle")

            metrics = self._collect_basic_metrics()
            if not metrics:
                raise MonitoringError("Failed to collect basic metrics")

            self.db_manager.insert_metrics(metrics)

            monitoring = self.config.monitoring
            processes = self._collect_process_information() if monitoring.enable_process_monitoring else []

            all_alerts = []
            all_alerts.extend(self._check_thresholds(metrics))

            if monitoring.enable_lolbin_detection and processes:
                all_alerts.extend(self._analyze_lolbins_activity(processes))

            all_alerts.extend(self._analyze_anomalies(metrics))

            if processes:
                all_alerts.extend(self._analyze_network_activity(processes))

            cycle_time = time.time() - cycle_start
            self.performance_history.append({
                'timestamp': time.time(),
                'cycle_time': cycle_time,
                'metrics_collected': len(metrics),
                'processes_analyzed': len(processes),
                'alerts_generated': len(all_alerts)
            })
            self.performance_history = self.performance_history[-100:]

            self.last_metrics = metrics

            logger.debug(f"Monitoring cycle completed in {cycle_time:.2f}s, {len(all_alerts)} alerts generated")
            return {
                'metrics': metrics,
                'alerts': all_alerts,
                'processes': [asdict(p) for p in processes],
                'processes_analyzed': len(processes),
                'cycle_time': cycle_time,
                'system_info': self.system_info
            }

        except MonitoringError:
            raise
        except Exception as e:
            logger.error(f"Error in monitoring cycle: {e}")
            raise MonitoringError(f"Monitoring cycle failed: {e}")

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get monitoring performance statistics"""
        if not self.performance_history:
            return {}

        cycle_times = [p['cycle_time'] for p in self.performance_history]

        return {
            'average_cycle_time': sum(cycle_times) / len(cycle_times),
            'max_cycle_time': max(cycle_times),
            'min_cycle_time': min(cycle_times),
            'total_cycles': len(self.performance_history),
            'last_cycle_time': cycle_times[-1],
            'last_processes_analyzed': self.performance_history[-1]['processes_analyzed']
        }

    def start(self):
        """Start the monitoring system"""
        self.running = True
        logger.info("Enhanced security monitor started")

    def stop(self):
        """Stop the monitoring system"""
        self.running = False
        logger.info("Enhanced security monitor stopped")
