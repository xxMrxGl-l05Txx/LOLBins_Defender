"""
LOLBin rule matching shared by the monitor, the API and the tests
"""
import json
import logging
import ntpath
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

RULES_FILE = Path(__file__).resolve().parent.parent / "monitor" / "lolbins_rules.json"

# Patterns that indicate remote code, obfuscation or defence evasion
HIGH_RISK_PATTERNS = (
    'downloadstring', 'invoke-expression', 'iex', 'encoded',
    'bypass', 'hidden', 'noprofile', 'javascript:', 'http://', 'https://'
)

SEVERITY_ORDER = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}

_rules_cache: Optional[List[Dict[str, Any]]] = None


def load_rules(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Load LOLBin rules from disk (the default file is cached)"""
    global _rules_cache

    if path is None and _rules_cache is not None:
        return _rules_cache

    rules_path = Path(path) if path else RULES_FILE
    try:
        with open(rules_path, 'r', encoding='utf-8') as f:
            rules = json.load(f)
    except Exception as e:
        logger.error(f"Error loading LOLBin rules from {rules_path}: {e}")
        return []

    if path is None:
        _rules_cache = rules
    return rules


def normalize_binary(name: str) -> str:
    """Reduce a process name or path to a lowercase basename without .exe"""
    base = ntpath.basename((name or '').strip().strip('"')).lower()
    return base[:-4] if base.endswith('.exe') else base


def determine_severity(rule: Dict[str, Any], pattern: str) -> str:
    """Determine alert severity for a matched rule pattern"""
    pattern_lower = pattern.lower()
    if any(risk in pattern_lower for risk in HIGH_RISK_PATTERNS):
        return 'CRITICAL'
    if rule.get('parent_process_hints'):
        return 'HIGH'
    return 'MEDIUM'


def find_rule(binary: str, rules: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    """Return the rule for a binary, if it is a known LOLBin"""
    target = normalize_binary(binary)
    if not target:
        return None
    for rule in rules if rules is not None else load_rules():
        if normalize_binary(rule.get('binary', '')) == target:
            return rule
    return None


def match_lolbin(binary: str, command: str,
                 rules: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    """
    Check a binary/command pair against the LOLBin rules.

    Returns None when the binary is not a LOLBin or no suspicious pattern
    matched, otherwise a dict with the rule, matched patterns and severity.
    """
    rule = find_rule(binary, rules)
    if not rule:
        return None

    command_lower = (command or '').lower()
    matched = [p for p in rule.get('command_patterns', []) if p.lower() in command_lower]
    if not matched:
        return None

    severity = max((determine_severity(rule, p) for p in matched), key=SEVERITY_ORDER.get)
    return {
        'rule': rule,
        'patterns': matched,
        'severity': severity,
    }


def is_lolbin_malicious(binary: str, command: str,
                        rules: Optional[List[Dict[str, Any]]] = None) -> bool:
    """True when the command line shows suspicious use of a LOLBin"""
    return match_lolbin(binary, command, rules) is not None
