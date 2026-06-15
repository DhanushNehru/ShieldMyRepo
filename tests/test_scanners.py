"""Tests for individual scanner modules."""

import json
import os
import pytest


def test_secrets_scanner_detects_aws_key(tmp_path):
    """Test that the secrets scanner detects AWS access keys."""
    from shieldmyrepo.scanners.secrets import SecretScanner

    test_file = tmp_path / "config.py"
    test_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')

    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))

    assert len(findings) >= 1
    assert any("AWS" in f.message for f in findings)


def test_secrets_scanner_detects_github_token(tmp_path):
    """Test that the secrets scanner detects GitHub tokens."""
    from shieldmyrepo.scanners.secrets import SecretScanner

    test_file = tmp_path / "script.sh"
    test_file.write_text('TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij')

    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))

    assert len(findings) >= 1
    assert any("GitHub" in f.message for f in findings)


def test_secrets_scanner_detects_new_patterns(tmp_path):
    """Test detection of OpenAI, Discord, Telegram, and Stripe publishable keys."""
    from shieldmyrepo.scanners.secrets import SecretScanner

    test_file = tmp_path / "secrets.env"
    # Construct tokens dynamically to avoid push protection false positives
    # These are test fixtures, not real secrets
    openai_key = "sk-" + "x" * 20 + "T3BlbkFJ" + "x" * 20
    discord_token = "M" + "y" * 23 + "." + "z" * 6 + "." + "a" * 27
    telegram_token = "123456789:" + "b" * 35
    stripe_key = "pk_live_" + "c" * 24
    test_file.write_text(
        f'OPENAI_KEY="{openai_key}"\n'
        f'DISCORD_TOKEN="{discord_token}"\n'
        f'TELEGRAM_TOKEN="{telegram_token}"\n'
        f'STRIPE_KEY="{stripe_key}"\n'
    )

    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))

    messages = [f.message for f in findings]
    assert any("OpenAI" in m for m in messages), f"Missing OpenAI detection: {messages}"
    assert any("Discord" in m for m in messages), f"Missing Discord detection: {messages}"
    assert any("Telegram" in m for m in messages), f"Missing Telegram detection: {messages}"
    assert any("Stripe Publishable" in m for m in messages), f"Missing Stripe detection: {messages}"


def test_secrets_scanner_clean_repo(tmp_path):
    """Test that clean repos pass the secrets scanner."""
    from shieldmyrepo.scanners.secrets import SecretScanner

    test_file = tmp_path / "app.py"
    test_file.write_text('print("Hello, world!")\n')

    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))

    assert len(findings) == 0


def test_dockerfile_scanner_detects_root(tmp_path):
    """Test that the Dockerfile scanner detects containers running as root."""
    from shieldmyrepo.scanners.dockerfile import DockerfileScanner

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.11\nRUN pip install flask\nCMD python app.py\n")

    scanner = DockerfileScanner()
    findings = scanner.scan(str(tmp_path))

    assert any("root" in f.message.lower() or "USER" in f.message for f in findings)


def test_dockerfile_scanner_detects_unpinned_image(tmp_path):
    """Test Dockerfile scanner detects unpinned base images."""
    from shieldmyrepo.scanners.dockerfile import DockerfileScanner

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM ubuntu:latest\nRUN apt-get update\n")

    scanner = DockerfileScanner()
    findings = scanner.scan(str(tmp_path))

    assert any("Unpinned" in f.message or "latest" in f.message for f in findings)


def test_gitignore_scanner_no_gitignore(tmp_path):
    """Test gitignore scanner flags missing .gitignore."""
    from shieldmyrepo.scanners.gitignore import GitignoreScanner

    scanner = GitignoreScanner()
    findings = scanner.scan(str(tmp_path))

    assert any(".gitignore" in f.message for f in findings)


def test_gitignore_scanner_detects_env_file(tmp_path):
    """Test gitignore scanner flags .env files not in .gitignore."""
    from shieldmyrepo.scanners.gitignore import GitignoreScanner

    env_file = tmp_path / ".env"
    env_file.write_text("SECRET_KEY=mysecret\n")

    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("*.pyc\n")

    scanner = GitignoreScanner()
    findings = scanner.scan(str(tmp_path))

    assert any(".env" in f.message for f in findings)


def test_dependency_scanner_unrequired(tmp_path):
    """Test dependency scanner handles projects without dependency files."""
    from shieldmyrepo.scanners.dependencies import DependencyScanner

    test_file = tmp_path / "main.py"
    test_file.write_text("print('hello')\n")

    scanner = DependencyScanner()
    findings = scanner.scan(str(tmp_path))

    # Should return an INFO finding about no dependency files
    assert any("No dependency" in f.message for f in findings)


def test_dependency_scanner_detects_unpinned(tmp_path):
    """Test dependency scanner detects unpinned Python dependencies."""
    from shieldmyrepo.scanners.dependencies import DependencyScanner

    req_file = tmp_path / "requirements.txt"
    req_file.write_text("flask\nrequests\n")

    scanner = DependencyScanner()
    findings = scanner.scan(str(tmp_path))

    assert any("Unpinned" in f.message for f in findings)


def test_secrets_scanner_tracks_scanned_files_count(tmp_path):
    """Test that the secrets scanner tracks the number of scanned files."""
    from shieldmyrepo.scanners.secrets import SecretScanner

    # Create multiple files with different extensions
    (tmp_path / "app.py").write_text('print("hello")\n')
    (tmp_path / "config.py").write_text('secret = "mysecretvalue"\n')  # Matches Generic Secret pattern
    (tmp_path / "main.py").write_text('import os\n')
    (tmp_path / "image.png").write_bytes(b'\x89PNG\r\n\x1a\n')  # Binary file, should be skipped

    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))

    # Should have scanned 3 files (excluding the .png binary file)
    assert scanner._scanned_files_count == 3
    # Should have detected the secret in config.py
    assert len(findings) >= 1


def test_scanner_base_initializes_scanned_files_count(tmp_path):
    """Test that ScannerBase initializes _scanned_files_count to 0."""
    from shieldmyrepo.scanners.secrets import SecretScanner

    scanner = SecretScanner()
    
    # Should be initialized to 0
    assert hasattr(scanner, '_scanned_files_count')
    assert scanner._scanned_files_count == 0
    
    # After scanning, should be updated
    (tmp_path / "test.py").write_text('print("test")\n')
    scanner.scan(str(tmp_path))
    
    assert scanner._scanned_files_count > 0
