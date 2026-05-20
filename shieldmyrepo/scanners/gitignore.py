"""
Scanner: Gitignore Check
Description: Validates .gitignore coverage for sensitive files.

Ensures that common sensitive files and directories are properly
excluded from version control.
"""

import os
from typing import Any, Dict, List

from shieldmyrepo.scanner_registry import Finding, ScannerBase, Severity


# Files that should typically be in .gitignore
SENSITIVE_PATTERNS: List[Dict[str, Any]] = [
    {
        "file": ".env",
        "description": "Environment variable file (may contain secrets)",
        "severity": Severity.HIGH,
    },
    {
        "file": ".env.local",
        "description": "Local environment file (may contain secrets)",
        "severity": Severity.HIGH,
    },
    {
        "file": ".env.production",
        "description": "Production environment file (likely contains secrets)",
        "severity": Severity.CRITICAL,
    },
    {
        "file": "id_rsa",
        "description": "SSH private key",
        "severity": Severity.CRITICAL,
    },
    {
        "file": "id_ed25519",
        "description": "SSH private key",
        "severity": Severity.CRITICAL,
    },
    {
        "file": ".pem",
        "description": "PEM certificate/key file",
        "severity": Severity.HIGH,
    },
    {
        "file": ".key",
        "description": "Private key file",
        "severity": Severity.HIGH,
    },
    {
        "file": ".p12",
        "description": "PKCS12 certificate file",
        "severity": Severity.HIGH,
    },
    {
        "file": "credentials.json",
        "description": "Credentials file",
        "severity": Severity.CRITICAL,
    },
    {
        "file": "service-account.json",
        "description": "Cloud service account credentials",
        "severity": Severity.CRITICAL,
    },
    {
        "file": ".htpasswd",
        "description": "Apache password file",
        "severity": Severity.HIGH,
    },
    {
        "file": "wp-config.php",
        "description": "WordPress configuration with database credentials",
        "severity": Severity.HIGH,
    },
]

RECOMMENDED_GITIGNORE_ENTRIES: List[str] = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "node_modules/",
    "__pycache__/",
    "*.pyc",
    ".DS_Store",
    "Thumbs.db",
    "dist/",
    "build/",
    "*.log",
]


class GitignoreScanner(ScannerBase):
    """Validates .gitignore coverage for sensitive files."""

    name = "Gitignore Check"
    description = "Ensures sensitive files are properly gitignored"

    def scan(self, repo_path: str) -> List[Finding]:
        findings: List[Finding] = []
        self._scanned_files_count = 0

        gitignore_path: str = os.path.join(repo_path, ".gitignore")

        # Check if .gitignore exists
        if not os.path.isfile(gitignore_path):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                message="No .gitignore file found",
                recommendation="Create a .gitignore file. Use gitignore.io to generate one for your project type.",
            ))
            gitignore_content = ""
        else:
            try:
                with open(gitignore_path, "r", encoding="utf-8") as f:
                    gitignore_content = f.read()
            except (IOError, OSError):
                gitignore_content = ""

        # Check for sensitive files that exist but aren't gitignored
        for pattern in SENSITIVE_PATTERNS:
            self._check_sensitive_file(
                repo_path, pattern, gitignore_content, findings
            )

        # Check for missing recommended entries
        if gitignore_content:
            missing: List[str] = []
            for entry in RECOMMENDED_GITIGNORE_ENTRIES:
                if entry not in gitignore_content:
                    missing.append(entry)

            if missing:
                findings.append(Finding(
                    severity=Severity.LOW,
                    message=f"Missing recommended .gitignore entries: {', '.join(missing[:5])}",
                    file=".gitignore",
                    recommendation="Consider adding these common patterns to your .gitignore.",
                ))

        return findings

    def _check_sensitive_file(
        self, repo_path: str, pattern: Dict[str, Any],
        gitignore_content: str, findings: List[Finding]
    ) -> None:
        """Check if a sensitive file exists and is not gitignored."""
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in {
                ".git", "node_modules", "__pycache__", "venv",
            }]

            for filename in files:
                self._scanned_files_count += 1
                matches: bool = False
                if filename == pattern["file"]:
                    matches = True
                elif filename.endswith(pattern["file"]):
                    matches = True

                if matches:
                    rel_path: str = os.path.relpath(
                        os.path.join(root, filename), repo_path
                    )

                    # Simple check if pattern is in .gitignore
                    if pattern["file"] not in gitignore_content and f"*{pattern['file']}" not in gitignore_content:
                        findings.append(Finding(
                            severity=pattern["severity"],
                            message=f"Sensitive file found and not gitignored: {rel_path} ({pattern['description']})",
                            file=rel_path,
                            recommendation=f"Add '{pattern['file']}' to .gitignore and remove the file from version control.",
                        ))
