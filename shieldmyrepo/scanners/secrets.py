"""
Scanner: Secret Detection
Description: Detects leaked API keys, tokens, passwords, and private keys.

This scanner uses regex patterns to identify common secret patterns
in source code files.
"""

import os
import re
from typing import List

from shieldmyrepo.scanner_registry import Finding, ScannerBase, Severity


# Regex patterns for common secrets
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": Severity.CRITICAL,
        "recommendation": "Remove the AWS key and rotate it immediately. Use environment variables or AWS IAM roles instead.",
    },
    {
        "name": "AWS Secret Key",
        "pattern": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
        "severity": Severity.CRITICAL,
        "recommendation": "Remove the AWS secret key and rotate it. Use AWS Secrets Manager or environment variables.",
    },
    {
        "name": "GitHub Token",
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "severity": Severity.CRITICAL,
        "recommendation": "Revoke this GitHub token immediately and generate a new one with minimal permissions.",
    },
    {
        "name": "Generic API Key",
        "pattern": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]",
        "severity": Severity.HIGH,
        "recommendation": "Move API keys to environment variables or a secrets manager.",
    },
    {
        "name": "Generic Secret",
        "pattern": r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "severity": Severity.HIGH,
        "recommendation": "Never hardcode secrets. Use environment variables or a secrets manager.",
    },
    {
        "name": "Private Key",
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "recommendation": "Remove private keys from the repository immediately. Use a secrets manager.",
    },
    {
        "name": "Slack Webhook",
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}",
        "severity": Severity.HIGH,
        "recommendation": "Remove Slack webhook URL and regenerate it. Store in environment variables.",
    },
    {
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
        "severity": Severity.MEDIUM,
        "recommendation": "Remove hardcoded JWT tokens. These may contain sensitive claims.",
    },
    {
        "name": "Database URL",
        "pattern": r"(?i)(mongodb|postgres|mysql|redis):\/\/[^\s'\"]+:[^\s'\"]+@",
        "severity": Severity.CRITICAL,
        "recommendation": "Remove database connection strings with credentials. Use environment variables.",
    },
    {
        "name": "Stripe Key",
        "pattern": r"sk_(live|test)_[A-Za-z0-9]{24,}",
        "severity": Severity.CRITICAL,
        "recommendation": "Revoke this Stripe key immediately. Use environment variables for payment keys.",
    },
    {
        "name": "Heroku API Key",
        "pattern": r"(?i)(heroku[_-]?api[_-]?key|heroku[_-]?key)\s*[:=]\s*['\"][0-9a-f]{40}['\"]",
        "severity": Severity.HIGH,
        "recommendation": "Remove Heroku API key and rotate it. Use environment variables or Heroku config vars.",
    },
    {
        "name": "NPM Token",
        "pattern": r"npm_[A-Za-z0-9]{36,}",
        "severity": Severity.HIGH,
        "recommendation": "Revoke this NPM token immediately. Use environment variables or npmrc with restricted permissions.",
    },
    {
        "name": "Twilio API Key",
        "pattern": r"SK[0-9a-fA-F]{32}",
        "severity": Severity.HIGH,
        "recommendation": "Remove Twilio API key and rotate it. Use environment variables for communication credentials.",
    },
    {
        "name": "SendGrid API Key",
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "severity": Severity.HIGH,
        "recommendation": "Remove SendGrid API key and rotate it. Use environment variables for email service credentials.",
    },
    {
        "name": "Google API Key",
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": Severity.HIGH,
        "recommendation": "Remove Google API key and restrict it in Google Cloud Console. Use environment variables.",
    },
]

# File extensions to skip
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".mp3", ".mp4", ".zip", ".tar", ".gz", ".pdf",
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".bin",
}

# Directories to skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", "venv", ".venv", "env",
    ".env", "dist", "build", ".eggs", "*.egg-info",
}


class SecretScanner(ScannerBase):
    """Detects leaked API keys, tokens, passwords, and private keys in source code."""

    name = "Secret Detection"
    description = "Scans for leaked API keys, tokens, and passwords"

    def scan(self, repo_path: str) -> List[Finding]:
        findings = []

        for root, dirs, files in os.walk(repo_path):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for filename in files:
                # Skip binary files
                ext = os.path.splitext(filename)[1].lower()
                if ext in SKIP_EXTENSIONS:
                    continue

                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, repo_path)

                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except (IOError, OSError):
                    continue

                for line_num, line in enumerate(content.split("\n"), 1):
                    for pattern_info in SECRET_PATTERNS:
                        try:
                            if re.search(pattern_info["pattern"], line):
                                findings.append(Finding(
                                    severity=pattern_info["severity"],
                                    message=f"{pattern_info['name']} detected",
                                    file=rel_path,
                                    line=line_num,
                                    recommendation=pattern_info["recommendation"],
                                ))
                        except re.error:
                            continue

        return findings
