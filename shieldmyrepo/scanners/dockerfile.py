"""
Scanner: Dockerfile Security
Description: Analyzes Dockerfiles for insecure practices.

Checks for running as root, unpinned base images, secrets in
build args, and other Docker security best practices.
"""

import os
from typing import List, Set

from shieldmyrepo.scanner_registry import Finding, ScannerBase, Severity


SKIP_DIRS: Set[str] = {
    ".git", "node_modules", "__pycache__", "venv",
}

DOCKERFILE_NAMES: Set[str] = {
    "dockerfile", "dockerfile.dev", "dockerfile.prod",
}

COMPOSE_FILE_NAMES: Set[str] = {
    "docker-compose.yml", "docker-compose.yaml", "compose.yml",
}

SECRET_ARG_WORDS: Set[str] = {
    "password", "secret", "key", "token", "api_key", "apikey", "passwd",
}


class DockerfileScanner(ScannerBase):
    """Analyzes Dockerfiles for security best practices."""

    name = "Dockerfile Security"
    description = "Checks Dockerfiles for insecure configurations"

    def scan(self, repo_path: str) -> List[Finding]:
        findings: List[Finding] = []
        self._scanned_files_count = 0

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for filename in files:
                if filename.lower() in DOCKERFILE_NAMES:
                    filepath: str = os.path.join(root, filename)
                    rel_path: str = os.path.relpath(filepath, repo_path)
                    self._scanned_files_count += 1

                    try:
                        with open(filepath, "r", encoding="utf-8") as f:
                            content = f.read()
                    except (IOError, OSError):
                        continue

                    findings.extend(self._check_dockerfile(content, rel_path))

                # Also check docker-compose files
                if filename.lower() in COMPOSE_FILE_NAMES:
                    filepath = os.path.join(root, filename)
                    rel_path = os.path.relpath(filepath, repo_path)
                    self._scanned_files_count += 1

                    try:
                        with open(filepath, "r", encoding="utf-8") as f:
                            content = f.read()
                    except (IOError, OSError):
                        continue

                    findings.extend(self._check_compose(content, rel_path))

        return findings

    def _check_dockerfile(self, content: str, rel_path: str) -> List[Finding]:
        """Check a Dockerfile for security issues."""
        findings: List[Finding] = []
        lines: List[str] = content.split("\n")
        has_user: bool = False

        for line_num, line in enumerate(lines, 1):
            stripped: str = line.strip()

            # Check for USER instruction
            if stripped.upper().startswith("USER "):
                has_user = True
                user: str = stripped[5:].strip()
                if user in ("root", "0"):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        message="Container explicitly runs as root user",
                        file=rel_path,
                        line=line_num,
                        recommendation="Create a non-root user and switch to it: RUN adduser -D appuser && USER appuser",
                    ))

            # Check for unpinned base image
            if stripped.upper().startswith("FROM "):
                image: str = stripped[5:].strip().split(" ")[0]
                if ":" not in image or image.endswith(":latest"):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        message=f"Unpinned base image: {image}",
                        file=rel_path,
                        line=line_num,
                        recommendation="Pin the base image to a specific version tag or digest for reproducible builds.",
                    ))

            # Check for secrets in build args
            if stripped.upper().startswith("ARG "):
                arg_name: str = stripped[4:].strip().split("=")[0].strip()
                if any(word in arg_name.lower() for word in SECRET_ARG_WORDS):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        message=f"Potential secret in build argument: {arg_name}",
                        file=rel_path,
                        line=line_num,
                        recommendation="Use Docker BuildKit secrets (--mount=type=secret) instead of ARG for sensitive values.",
                    ))

            # Check for ADD instead of COPY
            if stripped.upper().startswith("ADD ") and not stripped.upper().startswith("ADD --CHOWN"):
                if "http" not in stripped.lower() and ".tar" not in stripped.lower():
                    findings.append(Finding(
                        severity=Severity.LOW,
                        message="Using ADD instead of COPY",
                        file=rel_path,
                        line=line_num,
                        recommendation="Use COPY instead of ADD unless you specifically need ADD's auto-extraction feature.",
                    ))

            # Check for apt-get without --no-install-recommends
            if "apt-get install" in stripped and "--no-install-recommends" not in stripped:
                findings.append(Finding(
                    severity=Severity.LOW,
                    message="apt-get install without --no-install-recommends",
                    file=rel_path,
                    line=line_num,
                    recommendation="Add --no-install-recommends to reduce image size and attack surface.",
                ))

        # Check if no USER instruction found
        if not has_user:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                message="No USER instruction — container runs as root by default",
                file=rel_path,
                recommendation="Add a USER instruction to run as non-root: RUN adduser -D appuser && USER appuser",
            ))

        return findings

    def _check_compose(self, content: str, rel_path: str) -> List[Finding]:
        """Check docker-compose files for security issues."""
        findings: List[Finding] = []

        for line_num, line in enumerate(content.split("\n"), 1):
            stripped: str = line.strip()

            # Check for privileged mode
            if "privileged: true" in stripped:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    message="Container running in privileged mode",
                    file=rel_path,
                    line=line_num,
                    recommendation="Remove 'privileged: true'. Use specific capabilities with cap_add instead.",
                ))

            # Check for host network mode
            if "network_mode:" in stripped and "host" in stripped:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    message="Container using host network mode",
                    file=rel_path,
                    line=line_num,
                    recommendation="Use bridge networking (default) for better isolation.",
                ))

        return findings
