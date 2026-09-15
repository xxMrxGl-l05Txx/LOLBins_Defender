# Security Monitoring and Alerting System (LOLBins Defender)

A security monitoring, detection and alerting system for Windows that watches running processes for abuse of built-in "Living Off The Land" binaries (LOLBins) such as PowerShell, certutil and regsvr32, maps detections to MITRE ATT&CK, and presents them in a web dashboard.

## Components

| Component | Location | Role |
|-----------|----------|------|
| Monitor | `backend/monitor/enhanced_monitor.py` | Collects CPU/memory/disk/network metrics and process details; runs LOLBin, threshold, baseline and network checks |
| Detection | `backend/detection/` | LOLBin rule matching (`lolbin_rules.py`), statistical anomaly and spike detection, threat patterns and alert correlation (`enhanced_detector.py`) |
| Alerting | `backend/alerting/enhanced_dispatcher.py` | Desktop, email and webhook notifications with cooldown and hourly rate limiting |
| Reporting | `backend/reporting/enhanced_report_generator.py` | HTML (with embedded charts), CSV and JSON reports |
| API | `backend/api/enhanced_api.py` | REST API used by the dashboard |
| Service runner | `backend/utils/enhanced_service_runner.py` | Starts and coordinates everything above |
| Dashboard | `frontend/lolbas-defender-alert-main` | React web interface |

## Features

### Monitoring and detection
- LOLBin detection for 10 Windows binaries (`backend/monitor/lolbins_rules.json`), each mapped to a MITRE ATT&CK technique
- Each suspicious process is reported once, not on every scan
- CPU, memory and disk threshold alerts, plus deviation from a baseline captured at startup
- Statistical anomaly (z-score) and sudden-spike detection on system metrics
- Suspicious network connections (known reverse-shell ports, shells talking directly to public IPs)
- Correlation of related alerts (e.g. LOLBin execution combined with suspicious network activity)

### Alerting
- Desktop notifications (Windows tray balloon, macOS Notification Center, Linux `notify-send`)
- Email (SMTP) for HIGH and CRITICAL alerts, and webhook (HTTP POST) for all alerts
- Cooldown for repeated resource alerts and an hourly notification limit

### Reporting
- On-demand HTML, CSV and JSON reports, with options to include or omit details, command lines and MITRE references
- Scheduled daily (06:00) and weekly (Monday 07:00) HTML summaries
- Nightly cleanup of data older than the retention period

### Dashboard
- Live alert feed (refreshes every 5 seconds) with pop-up notifications for new alerts
- Alert triage: acknowledge, resolve, mark false positive, reopen
- Risk score, 7-day risk timeline, threat distribution and severity breakdown
- "Scan Now" and "Generate Test Alert" buttons to verify the pipeline end to end
- Report generation and download, and a settings page that edits the live configuration

## Requirements

- Python 3.9 or newer (tested with 3.13)
- Node.js 18 or newer for the dashboard (tested with 22)
- Windows for LOLBin detection (resource monitoring also works on Linux and macOS)
- Run the service as Administrator for full coverage: without elevation Windows hides the command lines of processes owned by other users

## Quick Start

1. Install the Python dependencies (from the project root):
   ```
   pip install -r requirements.txt
   ```

2. Start the monitoring service:
   ```
   python -m backend.utils.enhanced_service_runner
   ```
   The API is now available at `http://127.0.0.1:5000/api/v1/status`.

3. In a second terminal, start the dashboard:
   ```
   cd frontend/lolbas-defender-alert-main
   npm install
   npm run dev
   ```
   Open `http://localhost:8080`. The dev server proxies `/api` requests to the backend.

4. To check that everything is connected, open **Alerts** and click **Generate Test Alert**. The alert appears in the table and pops up as a notification.

## Configuration

Settings live in `config.json` in the project root. The dashboard's **Settings** page edits these values while the service is running:

| Section | Runtime-editable settings |
|---------|---------------------------|
| `monitoring` | `monitor_interval`, `cpu_threshold`, `memory_threshold`, `disk_threshold`, `enable_lolbin_detection`, `enable_process_monitoring` |
| `alerting` | `enable_desktop_notifications`, `enable_email_alerts`, `enable_webhook_alerts`, `alert_cooldown_seconds`, `max_alerts_per_hour` |
| general | `data_retention_days`, `enable_auto_cleanup`, `log_level` |

Email credentials, `webhook_url` and the whole `api` section can only be changed in the file. Restart the service after editing them.

```json
{
  "monitoring": { "cpu_threshold": 80.0, "monitor_interval": 60, "enable_lolbin_detection": true },
  "alerting": {
    "enable_desktop_notifications": true,
    "enable_email_alerts": false,
    "email_smtp_server": "smtp.example.com",
    "email_smtp_port": 587,
    "email_username": "alerts@example.com",
    "email_password": "app-password",
    "alert_cooldown_seconds": 300,
    "max_alerts_per_hour": 100
  },
  "api": {
    "host": "127.0.0.1",
    "port": 5000,
    "enable_rate_limiting": true,
    "rate_limit_per_minute": 100,
    "enable_authentication": false,
    "api_key": null
  }
}
```

**API access:** the API listens on `127.0.0.1` only. If you change `host` to `0.0.0.0` to allow remote access, set `enable_authentication: true` and an `api_key`. Clients then send the key in the `X-API-Key` header. For the dashboard, set `VITE_API_KEY` in `frontend/lolbas-defender-alert-main/.env.local`.

**Data location:** the database, logs and reports are stored in `data/`. Set the `SECMON_DATA_DIR` environment variable to use a different folder:

```
data/security_monitoring.db      SQLite database (alerts and metrics)
data/logs/security_monitoring.log
data/reports/                    Generated reports
```

## API Reference

All endpoints are under `/api/v1`. `status` and `system/health` never require an API key.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/status` | Service status, database statistics, last scan |
| GET | `/system/health` | Live CPU, memory, disk, network and process information |
| GET | `/statistics` | Alert counts for the last hour, day and week |
| POST | `/scan` | Run a monitoring cycle immediately |
| GET | `/alerts` | List alerts. Query: `limit`, `offset`, `severity`, `status`, `type`, `start_date`, `end_date` |
| DELETE | `/alerts` | Delete all alerts |
| POST | `/alerts/test` | Create a simulated alert. Body: `{"severity": "HIGH"}` |
| GET | `/alerts/{id}` | Alert details |
| PUT | `/alerts/{id}/status` | Body: `{"status": "new" \| "acknowledged" \| "resolved" \| "false_positive"}` |
| GET | `/metrics` | System metrics. Query: `hours`, `limit` |
| GET | `/dashboard/summary` | Counts, risk score, daily timeline and threat distribution. Query: `days` |
| GET | `/reports` | Previously generated reports |
| POST | `/reports/generate` | Body: `{"format": "html" \| "csv" \| "json", "days": 30, "include_commands": true}` (`days: 0` means all time) |
| GET | `/reports/download/{filename}` | Download a report |
| GET / PUT | `/config` | Read the configuration (secrets redacted) or update runtime-editable settings |

```bash
curl http://127.0.0.1:5000/api/v1/alerts?severity=CRITICAL&limit=10
```

## Windows Service Installation

Run `install_as_service.bat` as Administrator. The script:
1. Installs the Python dependencies
2. Downloads [NSSM](https://nssm.cc)
3. Registers `SecurityMonitoringService` to start automatically

Service output is written to `data\logs\`.

## Running the Tests

```
python -m pytest
```

The tests use temporary databases and config files, so they never touch `data/` or `config.json`.

## Project Layout

```
backend/
  core/          configuration, database, paths, exceptions
  monitor/       enhanced_monitor.py, lolbins_rules.json
  detection/     lolbin_rules.py, enhanced_detector.py
  alerting/      enhanced_dispatcher.py
  reporting/     enhanced_report_generator.py
  api/           enhanced_api.py
  utils/         enhanced_service_runner.py
frontend/lolbas-defender-alert-main/   React + Vite dashboard
tests/           API and monitoring tests
test_detector.py LOLBin rule tests
config.json
```

The following files belong to the original v1 prototype. The system described above does not use them:
- Root: `monitor.py`, `alert_dispatcher.py`, `report_generator.py`, `lolbinsService.ts`
- `backend/`: `monitor/monitor.py`, `detection/detector.py`, `alerting/alert_dispatcher.py`, `alerting/tkinter_notifier.py`, `api/api_server.py`, `reporting/report_generator.py`, `utils/service_runner.py`

## Adding Detection Rules

Add an entry to `backend/monitor/lolbins_rules.json` and restart the service:

```json
{
  "binary": "cscript.exe",
  "command_patterns": ["//e:jscript", "http://", "https://"],
  "parent_process_hints": ["winword.exe", "excel.exe"],
  "mitre_attack_id": "T1059.005",
  "description": "Windows Script Host executing remote or obfuscated scripts",
  "mitre_link": "https://attack.mitre.org/techniques/T1059/005/"
}
```

Command patterns are matched case-insensitively against the full command line. Severity depends on the pattern:
- **CRITICAL:** the pattern contains a remote URL or an obfuscation/bypass keyword
- **HIGH:** the rule lists parent process hints
- **MEDIUM:** otherwise

Test a rule directly:

```python
from backend.detection.lolbin_rules import match_lolbin
match_lolbin("cscript.exe", "cscript.exe //e:jscript http://example.com/a.js")
```

## Troubleshooting

- **Dashboard shows "Cannot reach the monitoring backend":** make sure the service is running and `http://127.0.0.1:5000/api/v1/status` responds. If you changed the API port, start the dashboard with `VITE_BACKEND_URL=http://127.0.0.1:<port>`.
- **Header says "API only - monitor not running":** the API was started on its own (`python backend/api/enhanced_api.py`). Start `enhanced_service_runner` instead to get scanning.
- **No LOLBin detections:** run the service as Administrator, and check that `enable_process_monitoring` and `enable_lolbin_detection` are on.
- **Too many resource alerts:** raise the thresholds or `alert_cooldown_seconds` in Settings.
- **Logs:** `data/logs/security_monitoring.log`. Use `--log-level DEBUG` for more detail.

## License

MIT License

## Changelog

### Version 2.0.0
- Enhanced monitor, detector, dispatcher, reporting and API modules
- Web dashboard connected to live backend data
- SQLite storage, runtime configuration and scheduled reports

### Version 1.0.0
- Initial prototype with basic monitoring, Tkinter alerts and CSV reports
