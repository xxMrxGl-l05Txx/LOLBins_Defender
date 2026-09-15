"""
Enhanced threat detection with behavioural and pattern analysis
"""
import logging
import time
import uuid
from datetime import timedelta
from typing import Dict, List, Any
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
import statistics

from ..core.config import ConfigManager
from ..core.database import DatabaseManager
from ..core.exceptions import DetectionError

logger = logging.getLogger(__name__)

@dataclass
class ThreatPattern:
    """Represents a threat pattern"""
    pattern_id: str
    name: str
    description: str
    severity: str
    indicators: List[str]
    mitre_techniques: List[str]
    confidence_threshold: float

@dataclass
class DetectionResult:
    """Result of threat detection analysis"""
    threat_detected: bool
    confidence_score: float
    threat_type: str
    indicators_matched: List[str]
    recommended_actions: List[str]
    metadata: Dict[str, Any]

class BehaviorAnalyzer:
    """Analyzes system behavior for anomalies"""

    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.metrics_history = deque(maxlen=window_size)
        self._last_timestamp = None

    def add_metrics(self, metrics: Dict[str, Any]):
        """Add a metrics sample to the rolling window (repeated samples are ignored)"""
        timestamp = metrics.get('timestamp', time.time())
        if timestamp == self._last_timestamp:
            return
        self._last_timestamp = timestamp

        self.metrics_history.append({
            'timestamp': timestamp,
            'cpu_percent': metrics.get('cpu_percent', 0),
            'memory_percent': metrics.get('memory_percent', 0),
            'disk_percent': metrics.get('disk_percent', 0),
            'process_count': metrics.get('process_count', 0),
            'network_connections': metrics.get('network_connections', 0)
        })

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies in the newest sample"""
        anomalies = []

        if len(self.metrics_history) < 10:
            return anomalies

        try:
            for metric_name in ('cpu_percent', 'memory_percent', 'process_count'):
                values = [m[metric_name] for m in self.metrics_history]
                anomalies.extend(self._detect_statistical_anomalies(values, metric_name))

            anomalies.extend(self._detect_sudden_spikes())

        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")

        return anomalies

    def _detect_statistical_anomalies(self, values: List[float], metric_name: str) -> List[Dict[str, Any]]:
        """Detect a statistical anomaly in the latest value using its z-score against history"""
        anomalies = []

        if len(values) < 5:
            return anomalies

        try:
            history, value = values[:-1], values[-1]
            mean_val = statistics.mean(history)
            stdev_val = statistics.stdev(history)

            if stdev_val == 0:
                return anomalies

            z_score = abs((value - mean_val) / stdev_val)

            if z_score > 2.5:  # Anomaly threshold
                anomalies.append({
                    'id': f"anomaly-{metric_name}-{uuid.uuid4().hex}",
                    'timestamp': time.time(),
                    'type': f'{metric_name}_anomaly',
                    'severity': 'HIGH' if z_score > 3.5 else 'MEDIUM',
                    'details': f"Statistical anomaly detected in {metric_name}: {value:.2f} (z-score: {z_score:.2f})",
                    'metadata': {
                        'metric': metric_name,
                        'value': value,
                        'mean': mean_val,
                        'stdev': stdev_val,
                        'z_score': z_score
                    }
                })

        except Exception as e:
            logger.error(f"Error in statistical anomaly detection: {e}")

        return anomalies

    def _detect_sudden_spikes(self) -> List[Dict[str, Any]]:
        """Detect sudden spikes in metrics"""
        anomalies = []

        if len(self.metrics_history) < 5:
            return anomalies

        try:
            recent_metrics = list(self.metrics_history)[-5:]

            for metric_name, unit in (('cpu_percent', '%'), ('memory_percent', '%'), ('process_count', '')):
                values = [m[metric_name] for m in recent_metrics]
                baseline = statistics.mean(values[:-2])
                current = values[-1]

                if current > baseline * 1.5 and current > 50:  # 50% increase and above 50
                    anomalies.append({
                        'id': f"spike-{metric_name}-{uuid.uuid4().hex}",
                        'timestamp': time.time(),
                        'type': f'{metric_name}_spike',
                        'severity': 'HIGH',
                        'details': f"Sudden spike detected in {metric_name}: {current:.2f}{unit} (baseline: {baseline:.2f}{unit})",
                        'metadata': {
                            'metric': metric_name,
                            'current_value': current,
                            'baseline_value': baseline,
                            'increase_factor': current / baseline if baseline > 0 else 0
                        }
                    })

        except Exception as e:
            logger.error(f"Error detecting spikes: {e}")

        return anomalies

class ThreatIntelligence:
    """Threat intelligence and pattern matching"""

    def __init__(self):
        self.threat_patterns = self._load_threat_patterns()
        self.ioc_database = self._load_ioc_database()

    def _load_threat_patterns(self) -> List[ThreatPattern]:
        """Load threat patterns from configuration"""
        return [
            ThreatPattern(
                pattern_id="lateral_movement",
                name="Lateral Movement",
                description="Potential lateral movement activity detected",
                severity="HIGH",
                indicators=["psexec", "wmic", "net use", "net view", "rdp"],
                mitre_techniques=["T1021", "T1077", "T1076"],
                confidence_threshold=0.7
            ),
            ThreatPattern(
                pattern_id="data_exfiltration",
                name="Data Exfiltration",
                description="Potential data exfiltration activity detected",
                severity="CRITICAL",
                indicators=["ftp", "scp", "curl", "wget", "powershell downloadstring"],
                mitre_techniques=["T1041", "T1048"],
                confidence_threshold=0.8
            ),
            ThreatPattern(
                pattern_id="persistence",
                name="Persistence Mechanism",
                description="Potential persistence mechanism detected",
                severity="HIGH",
                indicators=["schtasks", "reg add", "startup", "service"],
                mitre_techniques=["T1053", "T1547", "T1543"],
                confidence_threshold=0.6
            ),
            ThreatPattern(
                pattern_id="privilege_escalation",
                name="Privilege Escalation",
                description="Potential privilege escalation attempt detected",
                severity="CRITICAL",
                indicators=["runas", "sudo", "getsystem", "bypassuac"],
                mitre_techniques=["T1548", "T1134", "T1055"],
                confidence_threshold=0.8
            )
        ]

    def _load_ioc_database(self) -> Dict[str, List[str]]:
        """Load indicators of compromise database"""
        return {
            'malicious_ips': [
                '192.168.1.100',  # Example malicious IP
                '10.0.0.50'       # Example malicious IP
            ],
            'malicious_domains': [
                'malicious-site.com',
                'evil-domain.net'
            ],
            'malicious_hashes': [
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            ],
            'suspicious_processes': [
                'mimikatz.exe',
                'procdump.exe',
                'psexec.exe'
            ]
        }

    def analyze_command(self, command: str, binary: str = "") -> DetectionResult:
        """Analyze a command for threat patterns"""
        command_lower = command.lower()
        binary_lower = binary.lower()

        matched_patterns = []
        total_confidence = 0.0
        all_indicators = []

        for pattern in self.threat_patterns:
            confidence = 0.0
            matched_indicators = []

            for indicator in pattern.indicators:
                if indicator.lower() in command_lower or indicator.lower() in binary_lower:
                    confidence += 0.2
                    matched_indicators.append(indicator)

            if confidence >= pattern.confidence_threshold:
                matched_patterns.append(pattern)
                total_confidence = max(total_confidence, confidence)
                all_indicators.extend(matched_indicators)

        threat_detected = total_confidence > 0.5
        threat_type = matched_patterns[0].name if matched_patterns else "Unknown"

        return DetectionResult(
            threat_detected=threat_detected,
            confidence_score=total_confidence,
            threat_type=threat_type,
            indicators_matched=sorted(set(all_indicators)),
            recommended_actions=self._generate_recommendations(matched_patterns),
            metadata={
                'matched_patterns': [p.pattern_id for p in matched_patterns],
                'mitre_techniques': sorted(set(sum([p.mitre_techniques for p in matched_patterns], [])))
            }
        )

    def _generate_recommendations(self, patterns: List[ThreatPattern]) -> List[str]:
        """Generate recommended actions based on detected patterns"""
        recommendations = []

        pattern_ids = [p.pattern_id for p in patterns]

        if "lateral_movement" in pattern_ids:
            recommendations.extend([
                "Isolate affected system from network",
                "Check for unauthorized access to other systems",
                "Review network logs for suspicious connections"
            ])

        if "data_exfiltration" in pattern_ids:
            recommendations.extend([
                "Block outbound network connections",
                "Check for data loss prevention alerts",
                "Review file access logs"
            ])

        if "persistence" in pattern_ids:
            recommendations.extend([
                "Check scheduled tasks and startup programs",
                "Review registry modifications",
                "Scan for unauthorized services"
            ])

        if "privilege_escalation" in pattern_ids:
            recommendations.extend([
                "Check for unauthorized privilege changes",
                "Review user account activities",
                "Scan for privilege escalation tools"
            ])

        # Preserve order while removing duplicates
        return list(dict.fromkeys(recommendations))

class EnhancedSecurityDetector:
    """Enhanced security detector with advanced analysis capabilities"""

    def __init__(self, config_manager: ConfigManager, db_manager: DatabaseManager):
        self.config_manager = config_manager
        self.db_manager = db_manager
        self.config = config_manager.get_config()

        # Initialize components
        self.behavior_analyzer = BehaviorAnalyzer()
        self.threat_intelligence = ThreatIntelligence()

        # Detection state
        self.detection_history = deque(maxlen=1000)
        self.correlation_window = timedelta(minutes=10)
        self._reported_processes = set()

        # Performance tracking
        self.detection_stats = {
            'total_analyses': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'analysis_time_total': 0.0
        }

        logger.info("Enhanced security detector initialized")

    def analyze_metrics(self, metrics_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze metrics history for threats"""
        detections = []

        if not metrics_history:
            return detections

        try:
            analysis_start = time.time()

            self.behavior_analyzer.add_metrics(metrics_history[-1])
            detections.extend(self.behavior_analyzer.detect_anomalies())
            detections.extend(self._analyze_trends(metrics_history))

            analysis_time = time.time() - analysis_start
            self.detection_stats['total_analyses'] += 1
            self.detection_stats['analysis_time_total'] += analysis_time
            self.detection_stats['threats_detected'] += len(detections)

            logger.debug(f"Metrics analysis completed in {analysis_time:.3f}s, {len(detections)} detections")

        except Exception as e:
            logger.error(f"Error analyzing metrics: {e}")
            raise DetectionError(f"Metrics analysis failed: {e}")

        return detections

    def analyze_process_activity(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze process activity for threats"""
        detections = []
        active_keys = set()

        try:
            for process in processes:
                command = ' '.join(process.get('cmdline') or [])
                binary = process.get('name', '')

                result = self.threat_intelligence.analyze_command(command, binary)
                if not result.threat_detected:
                    continue

                key = (process.get('pid'), process.get('create_time'))
                active_keys.add(key)
                if key in self._reported_processes:
                    continue
                self._reported_processes.add(key)

                detections.append({
                    'id': f"threat-{uuid.uuid4().hex}",
                    'timestamp': time.time(),
                    'type': 'threat_pattern_detected',
                    'severity': self._map_confidence_to_severity(result.confidence_score),
                    'binary': binary,
                    'command': command,
                    'process_id': process.get('pid'),
                    'user_name': process.get('username'),
                    'mitre_id': (result.metadata.get('mitre_techniques') or [None])[0],
                    'details': f"Threat pattern detected: {result.threat_type} (confidence: {result.confidence_score:.2f})",
                    'metadata': {
                        'detection_result': asdict(result),
                        'process_info': process
                    }
                })

        except Exception as e:
            logger.error(f"Error analyzing process activity: {e}")

        self._reported_processes &= active_keys
        return detections

    def _analyze_trends(self, metrics_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze metrics trends for suspicious patterns"""
        detections = []

        if len(metrics_history) < 5:
            return detections

        try:
            memory_values = [m.get('memory_percent', 0) for m in metrics_history[-10:]]
            if len(memory_values) >= 10 and self._is_increasing_trend(memory_values, threshold=0.8):
                detections.append({
                    'id': f"trend-memory-{uuid.uuid4().hex}",
                    'timestamp': time.time(),
                    'type': 'memory_leak_pattern',
                    'severity': 'HIGH',
                    'details': "Potential memory leak detected - consistent memory increase pattern",
                    'metadata': {
                        'memory_values': memory_values,
                        'trend_analysis': 'increasing'
                    }
                })

            cpu_values = [m.get('cpu_percent', 0) for m in metrics_history[-10:]]
            if self._is_sustained_high(cpu_values, threshold=85, duration=5):
                detections.append({
                    'id': f"trend-cpu-{uuid.uuid4().hex}",
                    'timestamp': time.time(),
                    'type': 'sustained_high_cpu',
                    'severity': 'HIGH',
                    'details': "Sustained high CPU usage detected - possible cryptomining or DoS",
                    'metadata': {
                        'cpu_values': cpu_values,
                        'trend_analysis': 'sustained_high'
                    }
                })

        except Exception as e:
            logger.error(f"Error analyzing trends: {e}")

        return detections

    def _is_increasing_trend(self, values: List[float], threshold: float = 0.7) -> bool:
        """Check if values show an increasing trend"""
        if len(values) < 3:
            return False

        increases = sum(1 for i in range(1, len(values)) if values[i] > values[i - 1])
        return (increases / (len(values) - 1)) >= threshold

    def _is_sustained_high(self, values: List[float], threshold: float, duration: int) -> bool:
        """Check if values are sustained above threshold"""
        if len(values) < duration:
            return False

        return all(v >= threshold for v in values[-duration:])

    def _map_confidence_to_severity(self, confidence: float) -> str:
        """Map confidence score to severity level"""
        if confidence >= 0.9:
            return 'CRITICAL'
        elif confidence >= 0.7:
            return 'HIGH'
        elif confidence >= 0.5:
            return 'MEDIUM'
        else:
            return 'LOW'

    def correlate_events(self, alerts: List[Dict[str, Any]],
                        system_metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Correlate multiple events to identify complex attack patterns"""
        correlated_incidents = []

        if not alerts:
            return correlated_incidents

        try:
            now = time.time()
            recent_alerts = [
                alert for alert in alerts
                if isinstance(alert.get('timestamp'), (int, float))
                and now - alert['timestamp'] <= self.correlation_window.total_seconds()
            ]

            correlated_incidents.extend(self._identify_attack_patterns(recent_alerts))
            correlated_incidents.extend(self._identify_coordinated_attacks(recent_alerts))

        except Exception as e:
            logger.error(f"Error correlating events: {e}")

        return correlated_incidents

    def _identify_attack_patterns(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify known attack patterns from correlated alerts"""
        patterns = []

        alert_types = defaultdict(list)
        for alert in alerts:
            alert_types[alert.get('type', 'unknown')].append(alert)

        if ('lolbin_detection' in alert_types and
            'high_cpu' in alert_types and
            len(alerts) >= 3):

            patterns.append({
                'id': f"attack-pattern-{uuid.uuid4().hex}",
                'timestamp': time.time(),
                'type': 'multi_stage_attack',
                'severity': 'CRITICAL',
                'details': "Multi-stage attack pattern detected: LOLBin execution followed by resource consumption",
                'metadata': {
                    'related_alerts': [a.get('id') for a in alerts],
                    'attack_stages': list(alert_types.keys()),
                    'confidence': 0.85
                }
            })

        lolbin_alerts = alert_types.get('lolbin_detection', [])
        network_alerts = alert_types.get('suspicious_network_activity', [])

        if lolbin_alerts and network_alerts:
            patterns.append({
                'id': f"exfiltration-pattern-{uuid.uuid4().hex}",
                'timestamp': time.time(),
                'type': 'data_exfiltration_pattern',
                'severity': 'CRITICAL',
                'details': "Potential data exfiltration pattern: LOLBin execution with suspicious network activity",
                'metadata': {
                    'related_alerts': [a.get('id') for a in lolbin_alerts + network_alerts],
                    'confidence': 0.9
                }
            })

        return patterns

    def _identify_coordinated_attacks(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify coordinated attacks across multiple systems"""
        coordinated = []

        # Only alerts that name their system can be attributed to one
        system_alerts = defaultdict(list)
        for alert in alerts:
            if alert.get('system_name'):
                system_alerts[alert['system_name']].append(alert)

        if len(system_alerts) >= 2:
            total_alerts = sum(len(group) for group in system_alerts.values())

            if total_alerts >= 5:  # Threshold for coordinated attack
                coordinated.append({
                    'id': f"coordinated-attack-{uuid.uuid4().hex}",
                    'timestamp': time.time(),
                    'type': 'coordinated_attack',
                    'severity': 'CRITICAL',
                    'details': f"Coordinated attack detected across {len(system_alerts)} systems",
                    'metadata': {
                        'affected_systems': list(system_alerts.keys()),
                        'total_alerts': total_alerts,
                        'systems_count': len(system_alerts)
                    }
                })

        return coordinated

    def detect_threats(self, metrics_history: List[Dict[str, Any]],
                      recent_alerts: List[Dict[str, Any]],
                      processes: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Main threat detection method"""
        all_detections = []

        try:
            logger.debug("Starting comprehensive threat detection")

            all_detections.extend(self.analyze_metrics(metrics_history))

            if processes:
                all_detections.extend(self.analyze_process_activity(processes))

            all_detections.extend(self.correlate_events(
                recent_alerts, metrics_history[-1] if metrics_history else {}
            ))

            for detection in all_detections:
                self.detection_history.append({
                    'timestamp': detection.get('timestamp', time.time()),
                    'type': detection.get('type'),
                    'severity': detection.get('severity'),
                    'confidence': detection.get('metadata', {}).get('confidence', 0.5)
                })

            if all_detections:
                logger.warning(f"Detected {len(all_detections)} potential threats")

        except DetectionError:
            raise
        except Exception as e:
            logger.error(f"Error in threat detection: {e}")
            raise DetectionError(f"Threat detection failed: {e}")

        return all_detections

    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get detection performance statistics"""
        avg_analysis_time = (
            self.detection_stats['analysis_time_total'] /
            max(1, self.detection_stats['total_analyses'])
        )

        return {
            'total_analyses': self.detection_stats['total_analyses'],
            'threats_detected': self.detection_stats['threats_detected'],
            'false_positives': self.detection_stats['false_positives'],
            'average_analysis_time': avg_analysis_time,
            'detection_rate': (
                self.detection_stats['threats_detected'] /
                max(1, self.detection_stats['total_analyses'])
            ),
            'recent_detections': len(self.detection_history)
        }
