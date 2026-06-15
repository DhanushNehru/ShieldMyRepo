"""
Scanner: Secret Detection
Description: Detects leaked API keys, tokens, passwords, and private keys.

This scanner uses regex patterns to identify common secret patterns
in source code files.
"""

import os
import re
from typing import Any, Dict, List, Set

from shieldmyrepo.scanner_registry import Finding, ScannerBase, Severity


# Regex patterns for common secrets (pre-compiled for performance)
SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "AWS Access Key",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "compiled": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": Severity.CRITICAL,
        "recommendation": "Remove the AWS key and rotate it immediately. Use environment variables or AWS IAM roles instead.",
    },
    {
        "name": "AWS Secret Key",
        "pattern": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
        "compiled": re.compile(r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
        "severity": Severity.CRITICAL,
        "recommendation": "Remove the AWS secret key and rotate it. Use AWS Secrets Manager or environment variables.",
    },
    {
        "name": "GitHub Token",
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "compiled": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
        "severity": Severity.CRITICAL,
        "recommendation": "Revoke this GitHub token immediately and generate a new one with minimal permissions.",
    },
    {
        "name": "Generic API Key",
        "pattern": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]",
        "compiled": re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]"),
        "severity": Severity.HIGH,
        "recommendation": "Move API keys to environment variables or a secrets manager.",
    },
    {
        "name": "Generic Secret",
        "pattern": r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "compiled": re.compile(r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
        "severity": Severity.HIGH,
        "recommendation": "Never hardcode secrets. Use environment variables or a secrets manager.",
    },
    {
        "name": "Private Key",
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "compiled": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "severity": Severity.CRITICAL,
        "recommendation": "Remove private keys from the repository immediately. Use a secrets manager.",
    },
    {
        "name": "Slack Webhook",
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}",
        "compiled": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}"),
        "severity": Severity.HIGH,
        "recommendation": "Remove Slack webhook URL and regenerate it. Store in environment variables.",
    },
    {
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
        "compiled": re.compile(r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"),
        "severity": Severity.MEDIUM,
        "recommendation": "Remove hardcoded JWT tokens. These may contain sensitive claims.",
    },
    {
        "name": "Google / Firebase API Key",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "compiled": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "severity": Severity.CRITICAL,
        "recommendation": "Revoke the Google or Firebase API key immediately. Restrict the key to specific IPs or referrers.",
    },
    {
        "name": "GCP Service Account Key Info",
        "pattern": r"(?i)(\"type\":\s*\"service_account\"|\"private_key_id\":\s*\"[a-f0-9]{40}\")",
        "compiled": re.compile(r"(?i)(\"type\":\s*\"service_account\"|\"private_key_id\":\s*\"[a-f0-9]{40}\")"),
        "severity": Severity.HIGH,
        "recommendation": "Service Account JSON properties detected. Ensure private keys are never committed.",
    },
    {
        "name": "Database URL",
        "pattern": r"(?i)(mongodb|postgres|mysql|redis):\/\/[^\s'\"]+:[^\s'\"]+@",
        "compiled": re.compile(r"(?i)(mongodb|postgres|mysql|redis):\/\/[^\s'\"]+:[^\s'\"]+@"),
        "severity": Severity.CRITICAL,
        "recommendation": "Remove database connection strings with credentials. Use environment variables.",
    },
    {
        "name": "Stripe Key",
        "pattern": r"sk_(live|test)_[A-Za-z0-9]{24,}",
        "compiled": re.compile(r"sk_(live|test)_[A-Za-z0-9]{24,}"),
        "severity": Severity.CRITICAL,
        "recommendation": "Revoke this Stripe key immediately. Use environment variables for payment keys.",
    },
    {
        "name": "Azure Storage Account Key",
        "pattern": r"(?i)(DefaultEndpointsProtocol=https?|AccountKey)=[A-Za-z0-9+/=]{88}",
        "compiled": re.compile(r"(?i)(DefaultEndpointsProtocol=https?|AccountKey)=[A-Za-z0-9+/=]{88}"),
        "severity": Severity.CRITICAL,
        "recommendation": "Remove Azure storage account key and rotate it. Use Azure Key Vault or managed identities.",
    },
    {
        "name": "Azure AD Client Secret",
        "pattern": r"(?i)(azure[_-]?client[_-]?secret|client[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9_\-~.]{34}['\"]",
        "compiled": re.compile(r"(?i)(azure[_-]?client[_-]?secret|client[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9_\-~.]{34}['\"]"),
        "severity": Severity.CRITICAL,
        "recommendation": "Remove Azure AD client secret and rotate it. Use Azure Key Vault for secret management.",
    },
    {
        "name": "Azure Connection String",
        "pattern": r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=(core\.windows\.net|core\.chinacloudapi\.cn|core\.usgovcloudapi\.net)",
        "compiled": re.compile(r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=(core\.windows\.net|core\.chinacloudapi\.cn|core\.usgovcloudapi\.net)"),
        "severity": Severity.CRITICAL,
        "recommendation": "Remove Azure connection string and rotate credentials. Use managed identities or Azure Key Vault.",
    },
    {
        "name": "SendGrid API Key",
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "compiled": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        "severity": Severity.HIGH,
        "recommendation": "Remove SendGrid API key and regenerate it. Use environment variables for API keys.",
    },
    {
        "name": "Heroku API Key",
        "pattern": r"(?i)heroku[_-]?(api[_-]?)?key\s*[:=]\s*['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]",
        "compiled": re.compile(r"(?i)heroku[_-]?(api[_-]?)?key\s*[:=]\s*['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]"),
        "severity": Severity.HIGH,
        "recommendation": "Remove Heroku API key and regenerate it. Use environment variables for API keys.",
    },
    {
        "name": "Twilio API Key",
        "pattern": r"SK[0-9a-fA-F]{32}",
        "compiled": re.compile(r"SK[0-9a-fA-F]{32}"),
        "severity": Severity.HIGH,
        "recommendation": "Remove Twilio API key and rotate it. Use environment variables or Twilio Vault.",
    },
    {
        "name": "npm Access Token",
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "compiled": re.compile(r"npm_[A-Za-z0-9]{36}"),
        "severity": Severity.HIGH,
        "recommendation": "Revoke this npm access token immediately. Use environment variables for npm auth.",
    },
    {
        "name": "OpenAI API Key",
        "pattern": r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}",
        "compiled": re.compile(r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"),
        "severity": Severity.CRITICAL,
        "recommendation": "Revoke this OpenAI API key immediately. Use environment variables or a secrets manager.",
    },
    {
        "name": "Discord Bot Token",
        "pattern": r"[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}",
        "compiled": re.compile(r"[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}"),
        "severity": Severity.CRITICAL,
        "recommendation": "Revoke this Discord bot token immediately. Rotate in the Discord Developer Portal.",
    },
    {
        "name": "Telegram Bot Token",
        "pattern": r"\d{8,10}:[A-Za-z0-9_-]{35}",
        "compiled": re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}"),
        "severity": Severity.HIGH,
        "recommendation": "Revoke this Telegram bot token via @BotFather and regenerate.",
    },
    {
        "name": "Stripe Publishable Key",
        "pattern": r"pk_(live|test)_[A-Za-z0-9]{24,}",
        "compiled": re.compile(r"pk_(live|test)_[A-Za-z0-9]{24,}"),
        "severity": Severity.INFO,
        "recommendation": "Stripe publishable keys are public-facing. Ensure no sk_ secret keys are leaked. Use environment variables.",
    },
]

# File extensions to skip
SKIP_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".mp3", ".mp4", ".zip", ".tar", ".gz", ".pdf",
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".bin",
    ".whl", ".egg", ".jar", ".class",
}

# Directories to skip
SKIP_DIRS: Set[str] = {
    ".git", "node_modules", "__pycache__", "venv", ".venv", "env",
    ".env", "dist", "build", ".eggs", "*.egg-info",
}


class SecretScanner(ScannerBase):
    """Detects leaked API keys, tokens, passwords, and private keys in source code."""

    name = "Secret Detection"
    description = "Scans for leaked API keys, tokens, and passwords"

    def scan(self, repo_path: str) -> List[Finding]:
        findings: List[Finding] = []
        self._scanned_files_count = 0

        for root, dirs, files in os.walk(repo_path):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for filename in files:
                # Skip binary files
                ext: str = os.path.splitext(filename)[1].lower()
                if ext in SKIP_EXTENSIONS:
                    continue

                filepath: str = os.path.join(root, filename)
                rel_path: str = os.path.relpath(filepath, repo_path)
                self._scanned_files_count += 1

                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except (IOError, OSError):
                    continue

                for line_num, line in enumerate(content.split("\n"), 1):
                    for pattern_info in SECRET_PATTERNS:
                        try:
                            if pattern_info["compiled"].search(line):
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
