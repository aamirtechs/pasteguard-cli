import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pasteguard_cli import (  # noqa: E402
    mask_text,
    redact,
    scan_text,
    summary_counts,
    unmask_text,
)

CLI = [sys.executable, str(Path(__file__).resolve().parent.parent / "pasteguard_cli.py")]


def detectors(text):
    return [f["detector"] for f in scan_text(text)]


def test_email_detected():
    assert detectors("reach me at jane@example.com please") == ["EMAIL"]


def test_phone_detected():
    assert detectors("call 555-123-4567") == ["PHONE"]


def test_phone_with_parentheses():
    assert detectors("call (555) 123-4567") == ["PHONE"]


def test_ssn_detected():
    assert detectors("ssn 123-45-6789") == ["SSN"]


def test_credit_card_luhn_valid():
    assert detectors("card 4111 1111 1111 1111") == ["CREDIT_CARD"]


def test_credit_card_luhn_invalid_ignored():
    assert detectors("card 4111 1111 1111 1112") == []


def test_aws_key_detected():
    aws_key = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    assert detectors("key " + aws_key) == ["AWS_ACCESS_KEY"]


def test_github_token_detected():
    gh_token = "ghp_" + "abcdefghijklmnopqrstuvwxyz" + "1234567890"
    assert detectors("token " + gh_token) == ["GITHUB_TOKEN"]


def test_github_fine_grained_token_detected():
    token = "github_pat_" + "11ABCDEFGHIJKLMNO" + "0123456789_" + "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789abcd"
    assert detectors("token " + token) == ["GITHUB_TOKEN"]


def test_slack_token_detected():
    slack_token = "xoxb-" + "123456789012" + "-1234567890123-" + "AbCdEfGhIjKlMnOp"
    assert detectors("token " + slack_token) == ["SLACK_TOKEN"]


def test_private_key_header_detected():
    assert detectors("-----BEGIN PRIVATE KEY-----") == ["PRIVATE_KEY"]


def test_jwt_detected():
    token = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    assert detectors("bearer " + token) == ["JWT"]


def test_clean_text_has_no_findings():
    assert scan_text("hello world, nothing sensitive here") == []


def test_line_and_column_are_one_based():
    findings = scan_text("first line\nsecond jane@example.com")
    assert findings[0]["line"] == 2
    assert findings[0]["column"] == 8


def test_redact_keeps_last_four():
    assert redact("jane@example.com") == "************.com"


def test_redact_short_value():
    assert redact("abc") == "***"


def test_mask_replaces_and_mapping_restores():
    text = "mail jane@example.com and call 555-123-4567"
    findings = scan_text(text)
    masked, mapping = mask_text(text, findings)
    assert "[EMAIL-1]" in masked
    assert "[PHONE-1]" in masked
    assert "jane@example.com" not in masked
    assert unmask_text(masked, mapping) == text


def test_mask_numbers_repeat_detector_instances():
    text = "a@example.com b@example.com"
    masked, mapping = mask_text(text, scan_text(text))
    assert "[EMAIL-1]" in masked and "[EMAIL-2]" in masked
    assert len(mapping) == 2


def test_summary_counts():
    findings = scan_text("a@example.com b@example.com 555-123-4567")
    assert summary_counts(findings) == {"EMAIL": 2, "PHONE": 1}


def test_overlapping_matches_do_not_double_count():
    findings = scan_text("4111 1111 1111 1111")
    assert len(findings) == 1


def test_cli_default_output_lists_finding():
    result = subprocess.run(CLI + ["-"], input="mail jane@example.com\n", text=True, capture_output=True)
    assert result.returncode == 0
    assert "EMAIL" in result.stdout
    assert "jane@example.com" not in result.stdout


def test_cli_json_output():
    result = subprocess.run(CLI + ["--json", "-"], input="mail jane@example.com\n", text=True, capture_output=True)
    payload = json.loads(result.stdout)
    assert payload["findings"][0]["detector"] == "EMAIL"
    assert payload["findings"][0]["value_redacted"].endswith(".com")


def test_cli_check_exits_one_on_finding():
    result = subprocess.run(CLI + ["--check", "-"], input="mail jane@example.com\n", text=True, capture_output=True)
    assert result.returncode == 1


def test_cli_check_exits_zero_when_clean():
    result = subprocess.run(CLI + ["--check", "-"], input="hello world\n", text=True, capture_output=True)
    assert result.returncode == 0


def test_cli_report_counts():
    result = subprocess.run(CLI + ["--report", "-"], input="a@example.com b@example.com\n", text=True, capture_output=True)
    assert "EMAIL: 2" in result.stdout


def test_cli_mask_and_unmask_round_trip(tmp_path):
    mapping_file = tmp_path / "mapping.json"
    masked_file = tmp_path / "masked.txt"
    original = "mail jane@example.com\n"
    masked = subprocess.run(
        CLI + ["--mask", "--mapping-out", str(mapping_file), "-"],
        input=original, text=True, capture_output=True,
    )
    assert "[EMAIL-1]" in masked.stdout
    masked_file.write_text(masked.stdout)
    restored = subprocess.run(
        CLI + ["--unmask", "--mapping-in", str(mapping_file), str(masked_file)],
        text=True, capture_output=True,
    )
    assert restored.stdout.strip() == original.strip()


def test_cli_scans_file_argument(tmp_path):
    target = tmp_path / "note.txt"
    target.write_text("call 555-123-4567\n")
    result = subprocess.run(CLI + [str(target)], text=True, capture_output=True)
    assert "PHONE" in result.stdout


def test_cli_clean_file_reports_no_findings():
    result = subprocess.run(CLI + ["-"], input="nothing here\n", text=True, capture_output=True)
    assert "No findings." in result.stdout
