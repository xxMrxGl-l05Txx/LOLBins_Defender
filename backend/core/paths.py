"""
Well-known filesystem locations, anchored to the project root so the
system behaves the same regardless of the current working directory
"""
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Database, logs and reports live here; override with SECMON_DATA_DIR
_data_dir_override = os.environ.get("SECMON_DATA_DIR")
DATA_DIR = Path(_data_dir_override).expanduser().resolve() if _data_dir_override else PROJECT_ROOT / "data"
LOG_DIR = DATA_DIR / "logs"
REPORTS_DIR = DATA_DIR / "reports"
DEFAULT_CONFIG_FILE = PROJECT_ROOT / "config.json"


def system_disk_root() -> str:
    """Root of the system drive, used for disk usage metrics"""
    if os.name == 'nt':
        return os.environ.get('SystemDrive', 'C:') + '\\'
    return '/'
