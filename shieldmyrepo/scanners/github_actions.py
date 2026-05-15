"""
Scanner: GitHub Actions Security
Description: Detects insecure workflow configurations and supply chain risks.

Checks for common GitHub Actions security anti-patterns like
unpinned actions, dangerous permissions, and script injection risks.
"""

import os
import re
from typing import Any, Dict, List

import yaml

from shieldmyrepo.scanner_registry import Finding, ScannerBase, Severity


class GitHubActionsScanner(ScannerBase):
    """Audits GitHub Actions workflows for security misconfigurations."""

    name = "GitHub Actions"
    description = "Checks workflow files for security misconfigurations"

    def scan(self, repo_path: str) -> List[Finding]:
        findings: List[Finding] = []
        self._scanned_files_count = 0

        workflows_dir: str = os.path.join(repo_path, ".github", "workflows")
        if not os.path.isdir(workflows_dir):
            return findings

        for filename in os.listdir(workflows_dir):
            if not (filename.endswith(".yml") or filename.endswith(".yaml")):
                continue

            filepath: str = os.path.join(workflows_dir, filename)
            rel_path: str = os.path.relpath(filepath, repo_path)
            self._scanned_files_count += 1

            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    workflow = yaml.safe_load(content)
            except (IOError, yaml.YAMLError):
                continue

            if not isinstance(workflow, dict):
                continue

            # Check for dangerous permissions
            findings.extend(self._check_permissions(workflow, rel_path))

            # Check for unpinned actions
            findings.extend(self._check_unpinned_actions(content, rel_path))

            # Check for script injection
            findings.extend(self._check_script_injection(content, rel_path))

            # Check for pull_request_target
            findings.extend(self._check_pr_target(workflow, rel_path))

        return findings

    def _check_permissions(self, workflow: Dict[str, Any], rel_path: str) -> List[Finding]:
        """Check for overly permissive workflow permissions."""
        findings: List[Finding] = []

        perms = workflow.get("permissions")
        if perms == "write-all":
            findings.append(Finding(
                severity=Severity.HIGH,
                message="Workflow has 'write-all' permissions",
                file=rel_path,
                recommendation="Use least-privilege permissions. Specify only needed permissions explicitly.",
            ))

        # Check if no permissions are set (defaults to write for some events)
        if "permissions" not in workflow:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                message="No explicit permissions set — may default to write access",
                file=rel_path,
                recommendation="Add 'permissions: read-all' at the workflow level and grant write only where needed.",
            ))

        return findings

    def _check_unpinned_actions(self, content: str, rel_path: str) -> List[Finding]:
        """Check for actions using tags instead of SHA pinning."""
        findings: List[Finding] = []

        for line_num, line in enumerate(content.split("\n"), 1):
            match = re.search(r"uses:\s*([^@\s]+)@([^\s#]+)", line)
            if match:
                action: str = match.group(1)
                ref: str = match.group(2)

                # Skip if it's a SHA (40 hex chars)
                if re.match(r"^[a-f0-9]{40}$", ref):
                    continue

                # Skip local actions
                if action.startswith("./"):
                    continue

                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    message=f"Unpinned action: {action}@{ref}",
                    file=rel_path,
                    line=line_num,
                    recommendation=f"Pin {action} to a full SHA hash instead of tag '{ref}' to prevent supply chain attacks.",
                ))

        return findings

    def _check_script_injection(self, content: str, rel_path: str) -> List[Finding]:
        """Check for potential script injection via untrusted inputs."""
        findings: List[Finding] = []

        dangerous_contexts: List[str] = [
            "github.event.issue.title",
            "github.event.issue.body",
            "github.event.pull_request.title",
            "github.event.pull_request.body",
            "github.event.comment.body",
            "github.event.review.body",
            "github.head_ref",
        ]

        for line_num, line in enumerate(content.split("\n"), 1):
            for ctx in dangerous_contexts:
                if ctx in line and ("run:" in line or "${{" in line):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        message=f"Potential script injection: '{ctx}' used in run step",
                        file=rel_path,
                        line=line_num,
                        recommendation="Use an intermediate environment variable instead of inline expressions with untrusted input.",
                    ))

        return findings

    def _check_pr_target(self, workflow: Dict[str, Any], rel_path: str) -> List[Finding]:
        """Check for dangerous pull_request_target usage."""
        findings: List[Finding] = []

        trigger = workflow.get("on", workflow.get(True, {}))
        if isinstance(trigger, dict) and "pull_request_target" in trigger:
            findings.append(Finding(
                severity=Severity.HIGH,
                message="Workflow uses 'pull_request_target' trigger",
                file=rel_path,
                recommendation="pull_request_target runs with write permissions on forked PRs. "
                               "Ensure you're not checking out or running code from the PR head.",
            ))

        return findings
