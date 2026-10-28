#!/usr/bin/env python3
"""pasteguard-cli: scan text for PII and secrets before sharing or committing.

Zero dependencies. All detectors are deterministic regular expressions and
run locally. Nothing is sent over the network.
"""

import argparse
import json
import re
import sys
from collections import Counter


def luhn_valid(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# Each entry: (detector name, compiled pattern, optional validator).
_PATTERNS = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"), None),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), None),
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}"), None),
    ("GITHUB_TOKEN", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]+"), None),
    ("SLACK_TOKEN", re.compile(r"xox[baprs]-[A-Za-z0-9-]+"), None),
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), None),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), None),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){13,19}\b"), lambda v: 13 <= len(re.sub(r"\D", "", v)) <= 19 and luhn_valid(re.sub(r"\D", "", v))),
    ("PHONE", re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)"), None),
]

_PRIORITY = {name: i for i, (name, _pat, _val) in enumerate(_PATTERNS)}


def redact(value):
    """Return a redacted form showing only the last 4 characters."""
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


def scan_text(text):
    """Scan text and return a list of finding dicts in document order."""
    raw = []
    for name, pattern, validator in _PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if validator is not None and not validator(value):
                continue
            # Credit card digits must not be a phone-shaped fragment, and a
            # bare phone pattern must not swallow a longer digit run.
            raw.append({
                "detector": name,
                "value": value,
                "start": match.start(),
                "end": match.end(),
            })
    # Drop overlaps, keeping the earliest start and the highest priority.
    raw.sort(key=lambda f: (f["start"], _PRIORITY[f["detector"]]))
    kept = []
    for finding in raw:
        if any(finding["start"] < other["end"] and other["start"] < finding["end"] for other in kept):
            continue
        kept.append(finding)
    # Attach line and column (1 based).
    line_starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(i + 1)
    findings = []
    for finding in kept:
        line = 1
        for start in line_starts:
            if start <= finding["start"]:
                line = line_starts.index(start) + 1
            else:
                break
        col = finding["start"] - line_starts[line - 1] + 1
        findings.append({
            "detector": finding["detector"],
            "value": finding["value"],
            "value_redacted": redact(finding["value"]),
            "line": line,
            "column": col,
            "start": finding["start"],
            "end": finding["end"],
        })
    return findings


def mask_text(text, findings):
    """Replace each finding with a token like [EMAIL-1] and build a mapping."""
    counters = Counter()
    mapping = []
    parts = []
    cursor = 0
    for finding in findings:
        counters[finding["detector"]] += 1
        token = "[%s-%d]" % (finding["detector"], counters[finding["detector"]])
        parts.append(text[cursor:finding["start"]])
        parts.append(token)
        cursor = finding["end"]
        mapping.append({
            "token": token,
            "detector": finding["detector"],
            "value": finding["value"],
            "line": finding["line"],
            "column": finding["column"],
        })
    parts.append(text[cursor:])
    return "".join(parts), mapping


def unmask_text(text, mapping):
    """Restore original values from masked text using a mapping list."""
    result = text
    for entry in mapping:
        result = result.replace(entry["token"], entry["value"])
    return result


def summary_counts(findings):
    return dict(sorted(Counter(f["detector"] for f in findings).items()))


def format_report(findings):
    counts = summary_counts(findings)
    lines = ["Findings: %d" % len(findings)]
    for detector, count in counts.items():
        lines.append("%s: %d" % (detector, count))
    return "\n".join(lines)


def read_input(path):
    if path is None or path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pasteguard",
        description="Scan files or stdin for PII and secrets before sharing or committing.",
    )
    parser.add_argument("path", nargs="?", help="File to scan. Reads stdin when omitted.")
    parser.add_argument("--json", action="store_true", help="Print a machine readable JSON report.")
    parser.add_argument("--check", action="store_true", help="Exit 1 when any finding exists, else exit 0.")
    parser.add_argument("--mask", action="store_true", help="Print masked text instead of findings.")
    parser.add_argument("--mapping-out", metavar="FILE", help="Write the masking mapping JSON to FILE (use with --mask).")
    parser.add_argument("--unmask", action="store_true", help="Restore masked text using --mapping-in.")
    parser.add_argument("--mapping-in", metavar="FILE", help="Mapping JSON file to use with --unmask.")
    parser.add_argument("--report", action="store_true", help="Print a summary count per detector.")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    text = read_input(args.path)

    if args.unmask:
        if not args.mapping_in:
            print("error: --unmask requires --mapping-in FILE", file=sys.stderr)
            return 2
        with open(args.mapping_in, "r", encoding="utf-8") as handle:
            mapping = json.load(handle)
        if isinstance(mapping, dict):
            mapping = mapping.get("mapping", [])
        sys.stdout.write(unmask_text(text, mapping))
        return 0

    findings = scan_text(text)

    if args.mask:
        masked, mapping = mask_text(text, findings)
        sys.stdout.write(masked)
        if not masked.endswith("\n"):
            sys.stdout.write("\n")
        if args.mapping_out:
            with open(args.mapping_out, "w", encoding="utf-8") as handle:
                json.dump({"mapping": mapping}, handle, indent=2)
                handle.write("\n")
        if args.report:
            print(format_report(findings), file=sys.stderr)
    elif args.json:
        payload = {"findings": [{k: f[k] for k in ("detector", "value_redacted", "line", "column")} for f in findings]}
        if args.report:
            payload["summary"] = summary_counts(findings)
        print(json.dumps(payload, indent=2))
    elif args.report:
        print(format_report(findings))
        for finding in findings:
            print("%d:%d %s %s" % (finding["line"], finding["column"], finding["detector"], finding["value_redacted"]))
    else:
        if not findings:
            print("No findings.")
        for finding in findings:
            print("%d:%d %s %s" % (finding["line"], finding["column"], finding["detector"], finding["value_redacted"]))

    if args.check:
        return 1 if findings else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
