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


def test_secrets_scanner_detects_slack_webhook(tmp_path):
    """Test that the secrets scanner detects Slack Webhooks."""
    from shieldmyrepo.scanners.secrets import SecretScanner

    test_file = tmp_path / "notify.py"
    test_file.write_text('WEBHOOK = "https://hooks.slack.com/services/T12345678/B12345678/ABCD1234EFGH5678IJKL9012"')

    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))

    assert len(findings) >= 1
    assert any("Slack Webhook" in f.message for f in findings)


def test_secrets_scanner_detects_stripe_key(tmp_path):
    """Test that the secrets scanner detects Stripe API keys."""
    from shieldmyrepo.scanners.secrets import SecretScanner

    test_file = tmp_path / "payments.js"
    test_file.write_text('const stripeKey = "sk_live_51Mabc123DEF456ghi789jkl";')

    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))

    assert len(findings) >= 1
    assert any("Stripe Key" in f.message for f in findings)


def test_secrets_scanner_detects_heroku_api_key(tmp_path):
    """Test that the secrets scanner detects modern Heroku API keys."""
    from shieldmyrepo.scanners.secrets import SecretScanner

    test_file = tmp_path / "heroku_config.txt"
    test_file.write_text('api_key = "HRKU-01234567-89ab-cdef-0123-456789abcdef"')

    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))

    assert len(findings) >= 1
    assert any("Heroku API Key" in f.message for f in findings)


def test_secrets_scanner_detects_discord_token(tmp_path):
    """Test that the secrets scanner detects Discord Bot Tokens."""
    from shieldmyrepo.scanners.secrets import SecretScanner

    test_file = tmp_path / "discord_bot.py"
    test_file.write_text('TOKEN = "M12345678901234567890123.A1b2_c.123456789012345678901234567"')

    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))

    assert len(findings) >= 1
    assert any("Discord Bot Token" in f.message for f in findings)


def test_secrets_scanner_detects_telegram_token(tmp_path):
    """Test that the secrets scanner detects Telegram Bot Tokens."""
    from shieldmyrepo.scanners.secrets import SecretScanner

    test_file = tmp_path / "telebot.py"
    test_file.write_text('bot_token = "1234567890:ABCdef1234567890_XYZabcdef123456789"')

    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))

    assert len(findings) >= 1
    assert any("Telegram Bot Token" in f.message for f in findings)


def test_secrets_scanner_detects_aws_secret_key(tmp_path):
    """Test that the secrets scanner detects AWS Secret Keys."""
    from shieldmyrepo.scanners.secrets import SecretScanner
    test_file = tmp_path / "aws.config"
    test_file.write_text('aws_secret = "aBcD1234eFgH5678iJkL9012mNoP3456qRsT7890"')
    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))
    assert any("AWS Secret Key" in f.message for f in findings)

def test_secrets_scanner_detects_generic_api_key(tmp_path):
    """Test that the secrets scanner detects Generic API Keys."""
    from shieldmyrepo.scanners.secrets import SecretScanner
    test_file = tmp_path / "config.js"
    test_file.write_text('const API_KEY = "1234567890abcdefghij1234567890";')
    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))
    assert any("Generic API Key" in f.message for f in findings)

def test_secrets_scanner_detects_private_key(tmp_path):
    """Test that the secrets scanner detects Private Keys."""
    from shieldmyrepo.scanners.secrets import SecretScanner
    test_file = tmp_path / "id_rsa"
    test_file.write_text('-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA...\n-----END OPENSSH PRIVATE KEY-----')
    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))
    assert any("Private Key" in f.message for f in findings)

def test_secrets_scanner_detects_jwt(tmp_path):
    """Test that the secrets scanner detects JWT tokens."""
    from shieldmyrepo.scanners.secrets import SecretScanner
    test_file = tmp_path / "auth.py"
    test_file.write_text('token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"')
    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))
    assert any("JWT Token" in f.message for f in findings)

def test_secrets_scanner_detects_google_firebase_api_key(tmp_path):
    """Test that the secrets scanner detects Google/Firebase API keys."""
    from shieldmyrepo.scanners.secrets import SecretScanner
    test_file = tmp_path / "firebase.js"
    test_file.write_text('apiKey: "AIza12345678901234567890123456789012345"')
    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))
    assert any("Google / Firebase API Key" in f.message for f in findings)

def test_secrets_scanner_detects_gcp_service_account(tmp_path):
    """Test that the secrets scanner detects GCP Service Account Info."""
    from shieldmyrepo.scanners.secrets import SecretScanner
    test_file = tmp_path / "gcp.json"
    test_file.write_text('{\n  "type": "service_account",\n  "project_id": "my-project"\n}')
    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))
    assert any("GCP Service Account Key Info" in f.message for f in findings)

def test_secrets_scanner_detects_database_url(tmp_path):
    """Test that the secrets scanner detects Database URLs with credentials."""
    from shieldmyrepo.scanners.secrets import SecretScanner
    test_file = tmp_path / "db.py"
    test_file.write_text('DB_URI = "postgres://user:SuperSecretPassword123@localhost:5432/mydb"')
    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))
    assert any("Database URL" in f.message for f in findings)

def test_secrets_scanner_detects_azure_storage_key(tmp_path):
    """Test that the secrets scanner detects Azure Storage Account Keys."""
    from shieldmyrepo.scanners.secrets import SecretScanner
    test_file = tmp_path / "azure.py"
    test_file.write_text('AccountKey=1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678')
    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))
    assert any("Azure Storage Account Key" in f.message for f in findings)

def test_secrets_scanner_detects_azure_ad_secret(tmp_path):
    """Test that the secrets scanner detects Azure AD Client Secrets."""
    from shieldmyrepo.scanners.secrets import SecretScanner
    test_file = tmp_path / "azure_ad.py"
    test_file.write_text('AZURE_CLIENT_SECRET = "1234567890123456789012345678901234"')
    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))
    assert any("Azure AD Client Secret" in f.message for f in findings)

def test_secrets_scanner_detects_azure_connection_string(tmp_path):
    """Test that the secrets scanner detects Azure Connection Strings."""
    from shieldmyrepo.scanners.secrets import SecretScanner
    test_file = tmp_path / "azure_conn.py"
    test_file.write_text('conn_str = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;EndpointSuffix=core.windows.net"')
    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))
    assert any("Azure Connection String" in f.message for f in findings)