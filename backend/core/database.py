"""
Database management for the security monitoring system
"""
import sqlite3
import json
import logging
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union
from contextlib import contextmanager

from .paths import DATA_DIR

logger = logging.getLogger(__name__)

VALID_STATUSES = ('new', 'acknowledged', 'resolved', 'false_positive')
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')

# Columns matched by free-text alert search
SEARCH_COLUMNS = ('binary', 'command', 'details', 'type', 'system_name', 'user_name', 'mitre_id', 'id')

class DatabaseManager:
    """Manages SQLite database for storing alerts and metrics"""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else DATA_DIR / "security_monitoring.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self._init_database()

    def _init_database(self):
        """Initialize database with required tables"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Create alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    binary TEXT,
                    command TEXT,
                    process_id INTEGER,
                    user_name TEXT,
                    system_name TEXT,
                    mitre_id TEXT,
                    mitre_link TEXT,
                    details TEXT,
                    status TEXT DEFAULT 'new',
                    acknowledged_at REAL,
                    resolved_at REAL,
                    false_positive BOOLEAN DEFAULT 0,
                    metadata TEXT,
                    created_at REAL DEFAULT (julianday('now'))
                )
            ''')

            # Create metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    cpu_percent REAL,
                    memory_percent REAL,
                    disk_percent REAL,
                    network_bytes INTEGER,
                    process_count INTEGER,
                    active_connections INTEGER,
                    metadata TEXT,
                    created_at REAL DEFAULT (julianday('now'))
                )
            ''')

            # Create incidents table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    status TEXT DEFAULT 'open',
                    created_at REAL DEFAULT (julianday('now')),
                    updated_at REAL DEFAULT (julianday('now')),
                    resolved_at REAL,
                    assigned_to TEXT,
                    tags TEXT,
                    related_alerts TEXT
                )
            ''')

            # Create system_info table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT,
                    os_name TEXT,
                    os_version TEXT,
                    cpu_count INTEGER,
                    total_memory INTEGER,
                    disk_size INTEGER,
                    last_boot REAL,
                    updated_at REAL DEFAULT (julianday('now'))
                )
            ''')

            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)')

            conn.commit()
            logger.info(f"Database initialized at {self.db_path}")

    @contextmanager
    def _get_connection(self):
        """Get database connection with proper locking"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        record = dict(row)
        if record.get('metadata'):
            try:
                record['metadata'] = json.loads(record['metadata'])
            except (TypeError, ValueError):
                record['metadata'] = {}
        else:
            record['metadata'] = {}
        if 'false_positive' in record:
            record['false_positive'] = bool(record['false_positive'])
        return record

    def insert_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Insert a new alert into the database (fills in id/timestamp if missing)"""
        try:
            alert_data.setdefault('id', f"alert-{uuid.uuid4().hex}")
            alert_data.setdefault('timestamp', datetime.now().timestamp())
            details = alert_data.get('details')
            if details is not None and not isinstance(details, str):
                details = json.dumps(details, default=str)

            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute('''
                    INSERT OR IGNORE INTO alerts (
                        id, timestamp, type, severity, binary, command,
                        process_id, user_name, system_name, mitre_id, mitre_link,
                        details, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert_data.get('id'),
                    alert_data.get('timestamp'),
                    alert_data.get('type', 'unknown'),
                    str(alert_data.get('severity', 'MEDIUM')).upper(),
                    alert_data.get('binary'),
                    alert_data.get('command'),
                    alert_data.get('process_id'),
                    alert_data.get('user_name'),
                    alert_data.get('system_name'),
                    alert_data.get('mitre_id'),
                    alert_data.get('mitre_link'),
                    details,
                    json.dumps(alert_data.get('metadata', {}), default=str)
                ))

                conn.commit()
                if cursor.rowcount == 0:
                    logger.warning(f"Alert {alert_data.get('id')} already exists, skipped")
                    return False
                return True
        except Exception as e:
            logger.error(f"Error inserting alert: {e}")
            return False

    @staticmethod
    def _alert_filters(severity: Optional[str] = None,
                       status: Optional[Union[str, List[str]]] = None,
                       alert_type: Optional[str] = None,
                       start_time: Optional[float] = None,
                       end_time: Optional[float] = None,
                       search: Optional[str] = None) -> Tuple[str, List[Any]]:
        clause = " WHERE 1=1"
        params: List[Any] = []

        if severity:
            clause += " AND severity = ?"
            params.append(severity.upper())

        if status:
            statuses = [status] if isinstance(status, str) else list(status)
            clause += f" AND status IN ({', '.join('?' for _ in statuses)})"
            params.extend(statuses)

        if alert_type:
            clause += " AND type = ?"
            params.append(alert_type)

        if start_time is not None:
            clause += " AND timestamp >= ?"
            params.append(start_time)

        if end_time is not None:
            clause += " AND timestamp <= ?"
            params.append(end_time)

        if search:
            # Escape LIKE wildcards so the search text is matched literally
            escaped = search.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
            clause += " AND (" + " OR ".join(f"{column} LIKE ? ESCAPE '\\'" for column in SEARCH_COLUMNS) + ")"
            params.extend([f"%{escaped}%"] * len(SEARCH_COLUMNS))

        return clause, params

    def get_alerts(self, limit: int = 100, offset: int = 0,
                   severity: Optional[str] = None,
                   status: Optional[Union[str, List[str]]] = None,
                   start_time: Optional[float] = None,
                   end_time: Optional[float] = None,
                   alert_type: Optional[str] = None,
                   search: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get alerts with optional filtering, newest first"""
        try:
            clause, params = self._alert_filters(severity, status, alert_type, start_time, end_time, search)
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT * FROM alerts{clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    params + [limit, offset]
                )
                return [self._row_to_dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return []

    def count_alerts(self, severity: Optional[str] = None,
                     status: Optional[Union[str, List[str]]] = None,
                     start_time: Optional[float] = None,
                     end_time: Optional[float] = None,
                     alert_type: Optional[str] = None,
                     search: Optional[str] = None) -> int:
        """Count alerts matching the same filters as get_alerts"""
        try:
            clause, params = self._alert_filters(severity, status, alert_type, start_time, end_time, search)
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(f"SELECT COUNT(*) FROM alerts{clause}", params)
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error counting alerts: {e}")
            return 0

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get a single alert by id"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
                row = cursor.fetchone()
                return self._row_to_dict(row) if row else None
        except Exception as e:
            logger.error(f"Error getting alert {alert_id}: {e}")
            return None

    def get_alert_summaries(self, start_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """Lightweight alert rows (no command/metadata) for dashboard aggregation"""
        try:
            clause, params = self._alert_filters(start_time=start_time)
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"SELECT id, timestamp, type, severity, binary, status FROM alerts{clause} ORDER BY timestamp DESC",
                    params
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error getting alert summaries: {e}")
            return []

    def update_alert_status(self, alert_id: str, status: str,
                           acknowledged_at: Optional[float] = None,
                           resolved_at: Optional[float] = None) -> bool:
        """Update alert status"""
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}")

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                update_fields = ["status = ?", "false_positive = ?"]
                params: List[Any] = [status, 1 if status == 'false_positive' else 0]

                if acknowledged_at:
                    update_fields.append("acknowledged_at = ?")
                    params.append(acknowledged_at)

                if resolved_at:
                    update_fields.append("resolved_at = ?")
                    params.append(resolved_at)

                params.append(alert_id)

                query = f"UPDATE alerts SET {', '.join(update_fields)} WHERE id = ?"
                cursor.execute(query, params)

                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error updating alert status: {e}")
            return False

    def update_alerts_status(self, alert_ids: List[str], status: str,
                             timestamp: Optional[float] = None) -> int:
        """Update the status of several alerts at once, returning how many changed"""
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}")
        if not alert_ids:
            return 0

        timestamp = timestamp or datetime.now().timestamp()
        update_fields = ["status = ?", "false_positive = ?"]
        params: List[Any] = [status, 1 if status == 'false_positive' else 0]

        if status == 'acknowledged':
            update_fields.append("acknowledged_at = ?")
            params.append(timestamp)
        if status in ('resolved', 'false_positive'):
            update_fields.append("resolved_at = ?")
            params.append(timestamp)

        placeholders = ', '.join('?' for _ in alert_ids)
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"UPDATE alerts SET {', '.join(update_fields)} WHERE id IN ({placeholders})",
                    params + list(alert_ids)
                )
                conn.commit()
                return cursor.rowcount
        except Exception as e:
            logger.error(f"Error updating alert statuses: {e}")
            return 0

    def delete_all_alerts(self) -> int:
        """Delete every alert, returning how many were removed"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM alerts")
                conn.commit()
                return cursor.rowcount
        except Exception as e:
            logger.error(f"Error deleting alerts: {e}")
            return 0

    def insert_metrics(self, metrics_data: Dict[str, Any]) -> bool:
        """Insert system metrics"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute('''
                    INSERT INTO metrics (
                        timestamp, cpu_percent, memory_percent, disk_percent,
                        network_bytes, process_count, active_connections, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics_data.get('timestamp'),
                    metrics_data.get('cpu_percent'),
                    metrics_data.get('memory_percent'),
                    metrics_data.get('disk_percent'),
                    metrics_data.get('network_bytes'),
                    metrics_data.get('process_count'),
                    metrics_data.get('active_connections'),
                    json.dumps(metrics_data.get('metadata', {}), default=str)
                ))

                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error inserting metrics: {e}")
            return False

    def get_metrics(self, limit: int = 1000,
                    start_time: Optional[float] = None,
                    end_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """Get system metrics, newest first"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                query = "SELECT * FROM metrics WHERE 1=1"
                params: List[Any] = []

                if start_time is not None:
                    query += " AND timestamp >= ?"
                    params.append(start_time)

                if end_time is not None:
                    query += " AND timestamp <= ?"
                    params.append(end_time)

                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)

                cursor.execute(query, params)
                return [self._row_to_dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            return []

    def cleanup_old_data(self, retention_days: int = 30) -> bool:
        """Clean up old data based on retention policy"""
        try:
            cutoff_time = (datetime.now() - timedelta(days=retention_days)).timestamp()

            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Clean up old alerts
                cursor.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff_time,))
                alerts_deleted = cursor.rowcount

                # Clean up old metrics
                cursor.execute("DELETE FROM metrics WHERE timestamp < ?", (cutoff_time,))
                metrics_deleted = cursor.rowcount

                conn.commit()

                logger.info(f"Cleanup completed: {alerts_deleted} alerts, {metrics_deleted} metrics deleted")
                return True
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                stats = {}

                # Alert statistics
                cursor.execute("SELECT COUNT(*) FROM alerts")
                stats['total_alerts'] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'new'")
                stats['new_alerts'] = cursor.fetchone()[0]

                cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
                stats['alerts_by_severity'] = {row[0]: row[1] for row in cursor.fetchall()}

                cursor.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status")
                stats['alerts_by_status'] = {row[0]: row[1] for row in cursor.fetchall()}

                # Metrics statistics
                cursor.execute("SELECT COUNT(*) FROM metrics")
                stats['total_metrics'] = cursor.fetchone()[0]

                # Recent activity
                cursor.execute("""
                    SELECT COUNT(*) FROM alerts
                    WHERE timestamp > ?
                """, ((datetime.now() - timedelta(hours=24)).timestamp(),))
                stats['alerts_last_24h'] = cursor.fetchone()[0]

                return stats
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}
