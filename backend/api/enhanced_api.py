"""
Enhanced API server with comprehensive endpoints and security features
"""
import hmac
import logging
import os
import platform
import random
import shlex
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

if __package__ in (None, ''):
    # Allow running this file directly: python backend/api/enhanced_api.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import psutil
from flask import Blueprint, Flask, current_app, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import BadRequest, HTTPException, NotFound

from backend.core.config import ConfigManager, EDITABLE_FIELDS
from backend.core.database import DatabaseManager, SEVERITIES, VALID_STATUSES
from backend.core.exceptions import ConfigurationError
from backend.core.paths import system_disk_root
from backend.detection.lolbin_rules import (
    SEVERITY_ORDER, determine_severity, find_rule, load_rules, match_lolbin, normalize_binary
)
from backend.reporting.enhanced_report_generator import EnhancedSecurityReportGenerator, REPORT_FORMATS

logger = logging.getLogger(__name__)

API_VERSION = "2.0.0"
SEVERITY_WEIGHTS = {'CRITICAL': 20, 'HIGH': 10, 'MEDIUM': 3, 'LOW': 1}
ACTIVE_STATUSES = ('new', 'acknowledged')
MAX_BULK_IDS = 500

api = Blueprint('api', __name__, url_prefix='/api/v1')
legacy = Blueprint('legacy', __name__)


def _server() -> 'EnhancedSecurityAPIServer':
    return current_app.config['api_server']


def require_api_key(f):
    """Decorator to require API key authentication when it is enabled"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_config = _server().config_manager.get_config().api
        if api_config.enable_authentication:
            provided = request.headers.get('X-API-Key', '')
            if not api_config.api_key or not hmac.compare_digest(provided, api_config.api_key):
                return jsonify({"error": "Invalid or missing API key"}), 401
        return f(*args, **kwargs)
    return decorated_function


def _int_arg(name: str, default: int, minimum: int = 0, maximum: Optional[int] = None) -> int:
    raw = request.args.get(name)
    if raw in (None, ''):
        return default
    try:
        value = int(raw)
    except ValueError:
        raise BadRequest(f"{name} must be an integer")
    if value < minimum:
        raise BadRequest(f"{name} must be at least {minimum}")
    return min(value, maximum) if maximum is not None else value


def _time_arg(name: str) -> Optional[float]:
    """Accept an epoch timestamp (seconds) or an ISO 8601 date"""
    raw = request.args.get(name)
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(raw.replace('Z', '+00:00')).timestamp()
    except ValueError:
        raise BadRequest(f"{name} must be an ISO 8601 date or epoch seconds")


def _json_body() -> Dict[str, Any]:
    data = request.get_json(silent=True)
    if data is None:
        if request.get_data():
            raise BadRequest("Request body must be valid JSON")
        return {}
    if not isinstance(data, dict):
        raise BadRequest("Request body must be a JSON object")
    return data


def calculate_risk_score(alerts: List[Dict[str, Any]]) -> int:
    """Risk from open (new/acknowledged) alerts, weighted by severity and capped at 100"""
    return min(100, sum(
        SEVERITY_WEIGHTS.get(a.get('severity'), 0) for a in alerts if a.get('status') in ACTIVE_STATUSES
    ))


def _alert_label(alert: Dict[str, Any]) -> str:
    if alert.get('binary'):
        return normalize_binary(alert['binary']) + '.exe'
    return str(alert.get('type') or 'unknown').replace('_', ' ')


# ---------------------------------------------------------------------------
# System status
# ---------------------------------------------------------------------------

@api.route('/status', methods=['GET'])
def get_status():
    """Get system status and health information"""
    server = _server()
    api_config = server.config_manager.get_config().api

    return jsonify({
        "status": "healthy",
        "version": API_VERSION,
        "timestamp": datetime.now().isoformat(),
        "hostname": platform.node(),
        "uptime_seconds": time.time() - server.start_time,
        "database": {
            "connected": True,
            "statistics": server.db_manager.get_statistics()
        },
        "api": {
            "requests_total": server.api_stats['requests_total'],
            "errors_total": server.api_stats['errors_total'],
        },
        "service": server.status_provider() if server.status_provider else None,
        "capabilities": {
            "scan": server.scan_callback is not None,
            "authentication": api_config.enable_authentication,
        }
    })


@api.route('/system/health', methods=['GET'])
def get_system_health():
    """Get comprehensive system health information"""
    boot_time = psutil.boot_time()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(system_disk_root())

    try:
        connections = len(psutil.net_connections(kind='inet'))
    except (psutil.AccessDenied, OSError):
        connections = None

    network_io = psutil.net_io_counters()

    return jsonify({
        "system": {
            "hostname": platform.node(),
            "platform": platform.system(),
            "platform_version": platform.version(),
            "uptime_seconds": time.time() - boot_time,
            "boot_time": datetime.fromtimestamp(boot_time).isoformat()
        },
        "resources": {
            "cpu": {
                "percent": psutil.cpu_percent(interval=0.2),
                "count": psutil.cpu_count(),
                "load_avg": list(os.getloadavg()) if hasattr(os, 'getloadavg') else None
            },
            "memory": {
                "percent": memory.percent,
                "total": memory.total,
                "available": memory.available
            },
            "disk": {
                "path": system_disk_root(),
                "percent": disk.percent,
                "total": disk.total,
                "free": disk.free
            }
        },
        "network": {
            "connections": connections,
            "io_counters": network_io._asdict() if network_io else None
        },
        "processes": {
            "count": len(psutil.pids())
        }
    })


@api.route('/statistics', methods=['GET'])
@require_api_key
def get_statistics():
    """Get comprehensive system statistics"""
    server = _server()
    db = server.db_manager
    now = time.time()

    return jsonify({
        "database": db.get_statistics(),
        "alerts": {
            "last_hour": db.count_alerts(start_time=now - 3600),
            "last_day": db.count_alerts(start_time=now - 86400),
            "last_week": db.count_alerts(start_time=now - 7 * 86400)
        },
        "api": server.api_stats,
        "timestamp": datetime.now().isoformat()
    })


@api.route('/scan', methods=['POST'])
@require_api_key
def trigger_scan():
    """Request an immediate monitoring cycle"""
    server = _server()
    if not server.scan_callback:
        return jsonify({"error": "Scanning is only available when the API runs inside the monitoring service"}), 503

    server.scan_callback()
    return jsonify({"message": "Scan requested", "timestamp": datetime.now().isoformat()}), 202

# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@api.route('/alerts', methods=['GET'])
@require_api_key
def list_alerts():
    """Get alerts with filtering, search and pagination"""
    db = _server().db_manager

    limit = _int_arg('limit', 100, minimum=1, maximum=1000)
    offset = _int_arg('offset', 0)

    severity = (request.args.get('severity') or '').upper() or None
    if severity and severity not in SEVERITIES:
        raise BadRequest(f"severity must be one of {list(SEVERITIES)}")

    # status accepts a comma-separated list, e.g. status=new,acknowledged
    statuses = [s.strip() for s in (request.args.get('status') or '').split(',') if s.strip()]
    invalid = [s for s in statuses if s not in VALID_STATUSES]
    if invalid:
        raise BadRequest(f"status must be one of {list(VALID_STATUSES)}")

    search = (request.args.get('q') or '').strip()
    if len(search) > 200:
        raise BadRequest("q must be at most 200 characters")

    filters = {
        'severity': severity,
        'status': statuses or None,
        'alert_type': request.args.get('type') or None,
        'start_time': _time_arg('start_date'),
        'end_time': _time_arg('end_date'),
        'search': search or None,
    }

    alerts = db.get_alerts(limit=limit, offset=offset, **filters)
    total = db.count_alerts(**filters)

    return jsonify({
        "alerts": alerts,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "count": len(alerts),
            "total": total,
            "has_more": offset + len(alerts) < total
        },
        "filters": {
            "severity": severity,
            "status": statuses,
            "type": filters['alert_type'],
            "q": search or None,
            "start_date": request.args.get('start_date'),
            "end_date": request.args.get('end_date')
        }
    })


@api.route('/alerts', methods=['DELETE'])
@require_api_key
def clear_alerts():
    """Delete all alerts"""
    deleted = _server().db_manager.delete_all_alerts()
    logger.warning(f"All alerts cleared via API ({deleted} deleted)")
    return jsonify({"message": f"Deleted {deleted} alerts", "deleted": deleted})


@api.route('/alerts/status', methods=['PUT', 'PATCH'])
@require_api_key
def bulk_update_alert_status():
    """Update the status of several alerts at once"""
    data = _json_body()
    ids = data.get('ids')
    new_status = data.get('status')

    if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
        raise BadRequest("ids must be a non-empty list of alert ids")
    if len(ids) > MAX_BULK_IDS:
        raise BadRequest(f"At most {MAX_BULK_IDS} alerts can be updated at once")
    if new_status not in VALID_STATUSES:
        raise BadRequest(f"status must be one of {list(VALID_STATUSES)}")

    updated = _server().db_manager.update_alerts_status(list(dict.fromkeys(ids)), new_status, time.time())
    return jsonify({"message": f"Updated {updated} alerts", "updated": updated})


@api.route('/alerts/test', methods=['POST'])
@require_api_key
def create_test_alert():
    """Create a simulated LOLBin alert to verify the alert pipeline end to end"""
    server = _server()
    data = _json_body()

    severity = str(data.get('severity', 'HIGH')).upper()
    if severity not in SEVERITIES:
        raise BadRequest(f"severity must be one of {list(SEVERITIES)}")

    rules = load_rules()
    rule = random.choice(rules) if rules else {}
    binary = rule.get('binary', 'certutil.exe')
    pattern = (rule.get('command_patterns') or ['-urlcache'])[0]

    alert = {
        'id': f"test-{uuid.uuid4().hex}",
        'timestamp': time.time(),
        'type': 'test_alert',
        'severity': severity,
        'binary': binary,
        'command': f"{binary} {pattern} [simulated test command - nothing was executed]",
        'process_id': None,
        'user_name': None,
        'system_name': platform.node(),
        'mitre_id': rule.get('mitre_attack_id'),
        'mitre_link': rule.get('mitre_link'),
        'details': f"Test alert simulating suspicious {binary} usage. {rule.get('description', '')}".strip(),
        'metadata': {'test': True, 'rule': rule, 'patterns_matched': [pattern]},
    }

    server.submit_alerts([alert])
    return jsonify({"message": "Test alert created", "alert": server.db_manager.get_alert(alert['id'])}), 201


@api.route('/alerts/<alert_id>', methods=['GET'])
@require_api_key
def get_alert_details(alert_id):
    """Get detailed information about a specific alert"""
    alert = _server().db_manager.get_alert(alert_id)
    if not alert:
        raise NotFound("Alert not found")
    return jsonify({"alert": alert})


@api.route('/alerts/<alert_id>/status', methods=['PUT', 'PATCH'])
@require_api_key
def update_alert_status(alert_id):
    """Update alert status (acknowledge, resolve, etc.)"""
    db = _server().db_manager
    new_status = _json_body().get('status')

    if new_status not in VALID_STATUSES:
        raise BadRequest(f"status must be one of {list(VALID_STATUSES)}")

    now = time.time()
    success = db.update_alert_status(
        alert_id,
        new_status,
        acknowledged_at=now if new_status == 'acknowledged' else None,
        resolved_at=now if new_status in ('resolved', 'false_positive') else None
    )

    if not success:
        raise NotFound("Alert not found")

    return jsonify({"message": "Alert status updated successfully", "alert": db.get_alert(alert_id)})

# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

def _rule_summary(rule: Dict[str, Any]) -> Dict[str, Any]:
    patterns = rule.get('command_patterns', [])
    severities = [determine_severity(rule, p) for p in patterns] or ['MEDIUM']
    return {
        "binary": rule.get('binary'),
        "description": rule.get('description'),
        "mitre_attack_id": rule.get('mitre_attack_id'),
        "mitre_link": rule.get('mitre_link'),
        "command_patterns": patterns,
        "parent_process_hints": rule.get('parent_process_hints', []),
        # Highest severity any pattern in this rule can produce
        "severity": max(severities, key=SEVERITY_ORDER.get),
    }


@api.route('/rules', methods=['GET'])
@require_api_key
def list_rules():
    """List the LOLBin detection rules the monitor uses"""
    rules = load_rules()
    return jsonify({"rules": [_rule_summary(rule) for rule in rules], "count": len(rules)})


@api.route('/rules/test', methods=['POST'])
@require_api_key
def test_rule():
    """Check a command line against the rules without executing anything"""
    data = _json_body()
    command = str(data.get('command') or '')
    binary = str(data.get('binary') or '').strip()

    if len(command) > 8192:
        raise BadRequest("command must be at most 8192 characters")

    if not binary and command.strip():
        try:
            binary = shlex.split(command, posix=False)[0]
        except ValueError:
            binary = command.split()[0]
    if not binary:
        raise BadRequest("Provide a command line or a binary name")

    rule = find_rule(binary)
    match = match_lolbin(binary, command) if rule else None

    return jsonify({
        "binary": normalize_binary(binary) + '.exe',
        "known_binary": rule is not None,
        "matched": match is not None,
        "severity": match['severity'] if match else None,
        "patterns_matched": match['patterns'] if match else [],
        "rule": _rule_summary(rule) if rule else None,
    })

# ---------------------------------------------------------------------------
# Metrics and dashboard
# ---------------------------------------------------------------------------

@api.route('/metrics', methods=['GET'])
@require_api_key
def get_metrics():
    """Get system metrics with time range filtering"""
    db = _server().db_manager

    limit = _int_arg('limit', 100, minimum=1, maximum=1000)
    hours = _int_arg('hours', 24, minimum=1, maximum=24 * 365)

    end_time = time.time()
    start_time = end_time - (hours * 3600)
    metrics = db.get_metrics(limit=limit, start_time=start_time, end_time=end_time)

    return jsonify({
        "metrics": metrics,
        "time_range": {"start_time": start_time, "end_time": end_time, "hours": hours},
        "count": len(metrics)
    })


@api.route('/dashboard/summary', methods=['GET'])
@require_api_key
def get_dashboard_summary():
    """Dashboard summary: counts, risk score, daily timeline and threat distribution"""
    db = _server().db_manager
    days = _int_arg('days', 7, minimum=1, maximum=90)

    now = time.time()
    window_start = (datetime.now() - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    window_alerts = db.get_alert_summaries(start_time=window_start.timestamp())
    last_24h = [a for a in window_alerts if a['timestamp'] >= now - 86400]

    stats = db.get_statistics()
    by_status = {s: stats.get('alerts_by_status', {}).get(s, 0) for s in VALID_STATUSES}
    by_severity = {s: stats.get('alerts_by_severity', {}).get(s, 0) for s in SEVERITIES}

    timeline = []
    buckets = {}
    for i in range(days):
        day = (window_start + timedelta(days=i)).date().isoformat()
        entry = {"date": day, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "risk": 0}
        buckets[day] = entry
        timeline.append(entry)

    for alert in window_alerts:
        entry = buckets.get(datetime.fromtimestamp(alert['timestamp']).date().isoformat())
        if not entry:
            continue
        entry['total'] += 1
        severity = alert.get('severity')
        if severity in SEVERITIES:
            entry[severity.lower()] += 1
        entry['risk'] += SEVERITY_WEIGHTS.get(severity, 0)

    for entry in timeline:
        entry['risk'] = min(100, entry['risk'])

    distribution = [
        {"name": name, "value": count}
        for name, count in Counter(_alert_label(a) for a in window_alerts).most_common(8)
    ]

    latest_metrics = db.get_metrics(limit=1)
    current = latest_metrics[0] if latest_metrics else {}

    return jsonify({
        "alerts": {
            "total": stats.get('total_alerts', 0),
            "total_24h": len(last_24h),
            "new": by_status['new'],
            "active": by_status['new'] + by_status['acknowledged'],
            "critical_24h": sum(1 for a in last_24h if a['severity'] == 'CRITICAL'),
            "high_24h": sum(1 for a in last_24h if a['severity'] == 'HIGH'),
            "by_status": by_status,
            "by_severity": by_severity
        },
        "system": {
            "cpu_percent": current.get('cpu_percent'),
            "memory_percent": current.get('memory_percent'),
            "disk_percent": current.get('disk_percent'),
            "process_count": current.get('process_count'),
            "timestamp": current.get('timestamp')
        },
        "risk_score": calculate_risk_score(last_24h),
        "timeline": timeline,
        "distribution": distribution,
        "timestamp": datetime.now().isoformat()
    })

# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def _report_entry(report: Dict[str, Any]) -> Dict[str, Any]:
    return {**report, "download_url": f"/api/v1/reports/download/{report['filename']}"}


@api.route('/reports', methods=['GET'])
@require_api_key
def list_reports():
    """List previously generated reports"""
    reports = _server().report_generator.list_reports()
    return jsonify({"reports": [_report_entry(r) for r in reports]})


@api.route('/reports/generate', methods=['POST'])
@require_api_key
def generate_report():
    """Generate a security report (html, csv or json)"""
    server = _server()
    data = _json_body()

    if data.get('type', 'summary') != 'summary':
        raise BadRequest("Unsupported report type")

    report_format = str(data.get('format', 'html')).lower()
    if report_format not in REPORT_FORMATS:
        raise BadRequest(f"format must be one of {list(REPORT_FORMATS)}")

    try:
        days = int(data.get('days', 30))
    except (TypeError, ValueError):
        raise BadRequest("days must be an integer (0 for all time)")
    if days < 0:
        raise BadRequest("days must be 0 (all time) or greater")

    options = {key: data[key] for key in ('include_details', 'include_mitre', 'include_commands') if key in data}

    report_path = server.report_generator.generate(report_format, days=days, options=options)
    if not report_path:
        return jsonify({"error": "Failed to generate report"}), 500

    stat = report_path.stat()
    return jsonify({
        "message": "Report generated successfully",
        "report": _report_entry({
            "filename": report_path.name,
            "format": report_format,
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_mtime).isoformat()
        }),
        "download_url": f"/api/v1/reports/download/{report_path.name}"
    }), 201


def _send_report(reports_dir: Path, filename: str):
    # Reject anything that is not a bare file name (e.g. "..\\config.json" on Windows)
    if os.path.basename(filename) != filename or not (reports_dir / filename).is_file():
        raise NotFound("Report not found")
    return send_from_directory(reports_dir, filename, as_attachment=True, download_name=filename)


@api.route('/reports/download/<filename>', methods=['GET'])
@require_api_key
def download_report(filename):
    """Download a generated report"""
    return _send_report(_server().report_generator.output_dir, filename)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _editable_fields() -> Dict[str, List[str]]:
    return {(section or 'general'): sorted(names) for section, names in EDITABLE_FIELDS.items()}


@api.route('/config', methods=['GET'])
@require_api_key
def get_config():
    """Get current configuration (secrets redacted)"""
    config_manager = _server().config_manager
    return jsonify({"config": config_manager.to_dict(redact=True), "editable": _editable_fields()})


@api.route('/config', methods=['PUT', 'PATCH'])
@require_api_key
def update_config():
    """Update runtime-editable configuration values"""
    config_manager = _server().config_manager
    data = _json_body()
    if not data:
        raise BadRequest("No configuration values provided")

    try:
        saved = config_manager.update_config(data)
    except ConfigurationError as e:
        return jsonify({"error": str(e), "editable": _editable_fields()}), 400

    if not saved:
        return jsonify({"error": "Configuration applied but could not be saved to disk"}), 500

    return jsonify({"message": "Configuration updated successfully", "config": config_manager.to_dict(redact=True)})

# ---------------------------------------------------------------------------
# Legacy endpoints
# ---------------------------------------------------------------------------

@legacy.route('/download-csv', methods=['GET'])
@require_api_key
def download_csv_legacy():
    """Legacy CSV download endpoint"""
    generator = _server().report_generator
    days = request.args.get('days', default=30, type=int)

    csv_path = generator.generate_csv_report(days=days)
    if not csv_path:
        return jsonify({"error": "Failed to generate CSV report"}), 500

    return _send_report(generator.output_dir, csv_path.name)


class EnhancedSecurityAPIServer:
    """Enhanced API server with comprehensive security monitoring endpoints"""

    def __init__(self, config_manager: ConfigManager, db_manager: DatabaseManager,
                 report_generator: Optional[EnhancedSecurityReportGenerator] = None,
                 scan_callback: Optional[Callable[[], None]] = None,
                 alert_sink: Optional[Callable[[List[Dict[str, Any]]], Any]] = None,
                 status_provider: Optional[Callable[[], Dict[str, Any]]] = None):
        self.config_manager = config_manager
        self.db_manager = db_manager
        self.config = config_manager.get_config().api
        self.report_generator = report_generator or EnhancedSecurityReportGenerator(db_manager)
        self.scan_callback = scan_callback
        self.alert_sink = alert_sink
        self.status_provider = status_provider

        self.start_time = time.time()
        self.api_stats = {
            'requests_total': 0,
            'requests_by_endpoint': {},
            'errors_total': 0,
            'start_time': self.start_time
        }

        self.app = self._create_app()
        logger.info("Enhanced API server initialized")

    def _create_app(self) -> Flask:
        """Build the Flask application with middleware"""
        app = Flask(__name__)
        app.config['api_server'] = self
        app.json.sort_keys = False

        app.config['RATELIMIT_ENABLED'] = self.config.enable_rate_limiting
        app.config['RATELIMIT_HEADERS_ENABLED'] = True
        self.limiter = Limiter(
            get_remote_address,
            app=app,
            default_limits=[f"{self.config.rate_limit_per_minute} per minute"],
            storage_uri="memory://"
        )

        if self.config.enable_cors:
            CORS(app)

        app.register_blueprint(api)
        app.register_blueprint(legacy)

        @app.before_request
        def track_request():
            self.api_stats['requests_total'] += 1
            endpoint = request.endpoint or 'unknown'
            self.api_stats['requests_by_endpoint'][endpoint] = (
                self.api_stats['requests_by_endpoint'].get(endpoint, 0) + 1
            )

        @app.errorhandler(HTTPException)
        def handle_http_error(error: HTTPException):
            if error.code and error.code >= 500:
                self.api_stats['errors_total'] += 1
            return jsonify({"error": error.description}), error.code

        @app.errorhandler(Exception)
        def handle_error(error: Exception):
            self.api_stats['errors_total'] += 1
            logger.exception(f"Unhandled API error: {error}")
            return jsonify({"error": "Internal server error"}), 500

        return app

    def submit_alerts(self, alerts: List[Dict[str, Any]]):
        """Store and dispatch alerts through the service when available"""
        if self.alert_sink:
            self.alert_sink(alerts)
        else:
            for alert in alerts:
                self.db_manager.insert_alert(alert)

    def start(self):
        """Start the API server (blocking)"""
        logger.info(f"Starting enhanced API server on http://{self.config.host}:{self.config.port}/api/v1")
        self.app.run(
            host=self.config.host,
            port=self.config.port,
            debug=False,
            threaded=True,
            use_reloader=False
        )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    server = EnhancedSecurityAPIServer(ConfigManager(), DatabaseManager())
    server.start()
