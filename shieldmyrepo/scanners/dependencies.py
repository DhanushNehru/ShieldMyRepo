"""
Scanner: Dependency Vulnerability Check
Description: Checks package files for known vulnerable patterns.

Scans package.json, requirements.txt, Cargo.toml, go.mod, and
Gemfile for outdated or potentially vulnerable dependencies.
"""

import json
import os
import re
from typing import List

from shieldmyrepo.scanner_registry import Finding, ScannerBase, Severity


# Known vulnerable packages/patterns (simplified for demo — real impl would use an API)
KNOWN_VULNERABLE = {
    "python": {
        "pyyaml": {"below": "6.0", "severity": Severity.HIGH, "cve": "CVE-2020-14343"},
        "requests": {"below": "2.31.0", "severity": Severity.MEDIUM, "cve": "CVE-2023-32681"},
        "urllib3": {"below": "2.0.7", "severity": Severity.HIGH, "cve": "CVE-2023-45803"},
        "flask": {"below": "2.3.2", "severity": Severity.MEDIUM, "cve": "CVE-2023-30861"},
        "django": {"below": "4.2.7", "severity": Severity.HIGH, "cve": "CVE-2023-46695"},
        "jinja2": {"below": "3.1.3", "severity": Severity.HIGH, "cve": "CVE-2024-22195"},
        "pillow": {"below": "10.2.0", "severity": Severity.HIGH, "cve": "CVE-2023-50447"},
        "cryptography": {"below": "42.0.0", "severity": Severity.HIGH, "cve": "CVE-2024-0727"},
    },
    "node": {
        "lodash": {"below": "4.17.21", "severity": Severity.HIGH, "cve": "CVE-2021-23337"},
        "axios": {"below": "1.6.0", "severity": Severity.MEDIUM, "cve": "CVE-2023-45857"},
        "express": {"below": "4.18.2", "severity": Severity.MEDIUM, "cve": "CVE-2024-29041"},
        "jsonwebtoken": {"below": "9.0.0", "severity": Severity.CRITICAL, "cve": "CVE-2022-23529"},
        "minimatch": {"below": "3.1.2", "severity": Severity.HIGH, "cve": "CVE-2022-3517"},
        "semver": {"below": "7.5.2", "severity": Severity.MEDIUM, "cve": "CVE-2022-25883"},
    },
}

DEPENDENCY_FILES = {
    "requirements.txt": "python",
    "Pipfile": "python",
    "setup.py": "python",
    "pyproject.toml": "python",
    "package.json": "node",
    "Cargo.toml": "rust",
    "go.mod": "go",
    "Gemfile": "ruby",
    "pom.xml": "java",
    "build.gradle": "java",
}


class DependencyScanner(ScannerBase):
    """Checks dependency files for known vulnerabilities and bad practices."""

    name = "Dependency Check"
    description = "Scans package files for known vulnerabilities"

    def scan(self, repo_path: str) -> List[Finding]:
        findings = []

        for root, dirs, files in os.walk(repo_path):
            # Skip common non-project directories
            dirs[:] = [d for d in dirs if d not in {
                ".git", "node_modules", "__pycache__", "venv", ".venv",
                "dist", "build", ".eggs",
            }]

            for filename in files:
                if filename in DEPENDENCY_FILES:
                    filepath = os.path.join(root, filename)
                    rel_path = os.path.relpath(filepath, repo_path)
                    ecosystem = DEPENDENCY_FILES[filename]

                    try:
                        with open(filepath, "r", encoding="utf-8") as f:
                            content = f.read()
                    except (IOError, OSError):
                        continue

                    # Check for known vulnerable packages
                    if ecosystem == "node" and filename == "package.json":
                        findings.extend(self._check_package_json(content, rel_path))
                    elif ecosystem == "python" and filename == "requirements.txt":
                        findings.extend(self._check_requirements_txt(content, rel_path))

                    # Check for unpinned dependencies
                    if filename == "requirements.txt":
                        findings.extend(self._check_unpinned_python(content, rel_path))
                    elif filename == "package.json":
                        findings.extend(self._check_unpinned_node(content, rel_path))

        # Check if no dependency files found
        if not any(
            os.path.exists(os.path.join(repo_path, f))
            for f in DEPENDENCY_FILES
        ):
            findings.append(Finding(
                severity=Severity.INFO,
                message="No dependency files found",
                recommendation="This scanner works best with projects that have dependency files.",
            ))

        return findings

    def _check_package_json(self, content: str, rel_path: str) -> List[Finding]:
        """Check package.json for known vulnerable packages."""
        findings = []
        try:
            data = json.loads(content)
            all_deps = {}
            all_deps.update(data.get("dependencies", {}))
            all_deps.update(data.get("devDependencies", {}))

            known = KNOWN_VULNERABLE.get("node", {})
            for pkg, version in all_deps.items():
                if pkg.lower() in known:
                    vuln = known[pkg.lower()]
                    findings.append(Finding(
                        severity=vuln["severity"],
                        message=f"Potentially vulnerable package: {pkg}@{version} ({vuln['cve']})",
                        file=rel_path,
                        recommendation=f"Update {pkg} to version {vuln['below']} or higher.",
                    ))
        except json.JSONDecodeError:
            pass
        return findings

    def _check_requirements_txt(self, content: str, rel_path: str) -> List[Finding]:
        """Check requirements.txt for known vulnerable packages."""
        findings = []
        known = KNOWN_VULNERABLE.get("python", {})

        for line_num, line in enumerate(content.split("\n"), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Parse package name
            match = re.match(r"^([a-zA-Z0-9_-]+)", line)
            if match:
                pkg = match.group(1).lower()
                if pkg in known:
                    vuln = known[pkg]
                    findings.append(Finding(
                        severity=vuln["severity"],
                        message=f"Potentially vulnerable package: {line} ({vuln['cve']})",
                        file=rel_path,
                        line=line_num,
                        recommendation=f"Update {pkg} to version {vuln['below']} or higher.",
                    ))
        return findings

    def _check_unpinned_python(self, content: str, rel_path: str) -> List[Finding]:
        """Check for unpinned Python dependencies."""
        findings = []
        for line_num, line in enumerate(content.split("\n"), 1):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if "==" not in line and ">=" not in line and "<=" not in line:
                findings.append(Finding(
                    severity=Severity.LOW,
                    message=f"Unpinned dependency: {line}",
                    file=rel_path,
                    line=line_num,
                    recommendation="Pin dependency versions for reproducible builds (e.g., package==1.2.3).",
                ))
        return findings

    def _check_unpinned_node(self, content: str, rel_path: str) -> List[Finding]:
        """Check for widely unpinned Node.js dependencies."""
        findings = []
        try:
            data = json.loads(content)
            all_deps = {}
            all_deps.update(data.get("dependencies", {}))
            all_deps.update(data.get("devDependencies", {}))

            for pkg, version in all_deps.items():
                if version == "*" or version == "latest":
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        message=f"Wildcard dependency version: {pkg}@{version}",
                        file=rel_path,
                        recommendation=f"Pin {pkg} to a specific version range instead of '{version}'.",
                    ))
        except json.JSONDecodeError:
            pass
        return findings
