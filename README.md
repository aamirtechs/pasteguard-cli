# pasteguard-cli

A zero dependency Python CLI that scans files and stdin for personal data and secrets before you share a file or commit it. It is a command line companion to the BeforeYouPaste idea: check text first, mask it when you need to share it, and restore it later with your own mapping file.

Everything runs locally with deterministic regular expressions. There are no network calls, and JSON reports redact each value to its last 4 characters.

## Detectors

| Detector | What it finds |
| --- | --- |
| EMAIL | Email addresses |
| PHONE | US phone numbers |
| SSN | US Social Security numbers in 123-45-6789 form |
| CREDIT_CARD | Card numbers that pass the Luhn check |
| AWS_ACCESS_KEY | AWS access keys starting with AKIA |
| GITHUB_TOKEN | Classic and fine grained GitHub tokens |
| SLACK_TOKEN | Slack tokens starting with xoxb, xoxp, xoxa, xoxr, or xoxs |
| PRIVATE_KEY | Private key block headers |
| JWT | JWT shaped tokens |

## Usage

```sh
python3 pasteguard_cli.py <file>
python3 pasteguard_cli.py --json <file>
python3 pasteguard_cli.py --check <file>
python3 pasteguard_cli.py --report <file>
python3 pasteguard_cli.py --mask --mapping-out mapping.json <file>
python3 pasteguard_cli.py --unmask --mapping-in mapping.json <masked-file>
echo "text to check" | python3 pasteguard_cli.py
```

With no file argument, the tool reads stdin. `--check` exits 1 when any finding exists and 0 when the input is clean, so it fits in CI. `--report` prints a count per detector.

## Real output

The example files use fake values only. Scanning `examples/sample.txt`:

```text
$ python3 pasteguard_cli.py examples/sample.txt
1:10 EMAIL ****************.com
2:8 PHONE ********4567
3:10 AWS_ACCESS_KEY ****************MPLE
4:15 GITHUB_TOKEN ************************************7890
```

JSON report for the same file:

```text
$ python3 pasteguard_cli.py --json examples/sample.txt
{
  "findings": [
    {
      "detector": "EMAIL",
      "value_redacted": "****************.com",
      "line": 1,
      "column": 10
    },
    {
      "detector": "PHONE",
      "value_redacted": "********4567",
      "line": 2,
      "column": 8
    },
    {
      "detector": "AWS_ACCESS_KEY",
      "value_redacted": "****************MPLE",
      "line": 3,
      "column": 10
    },
    {
      "detector": "GITHUB_TOKEN",
      "value_redacted": "************************************7890",
      "line": 4,
      "column": 15
    }
  ]
}
```

Summary report for the same file:

```text
$ python3 pasteguard_cli.py --report examples/sample.txt
Findings: 4
AWS_ACCESS_KEY: 1
EMAIL: 1
GITHUB_TOKEN: 1
PHONE: 1
1:10 EMAIL ****************.com
2:8 PHONE ********4567
3:10 AWS_ACCESS_KEY ****************MPLE
4:15 GITHUB_TOKEN ************************************7890
```

Masking the same file:

```text
$ python3 pasteguard_cli.py --mask --mapping-out /tmp/pg-mapping.json examples/sample.txt
Contact: [EMAIL-1]
Phone: [PHONE-1]
AWS key: [AWS_ACCESS_KEY-1]
GitHub token: [GITHUB_TOKEN-1]
Note: this file is only a test fixture with fake values.
```

The mapping file lets the owner restore the original text with `--unmask --mapping-in mapping.json`. Keep mapping files private: they contain the original values.

Checking a clean file:

```text
$ python3 pasteguard_cli.py --check examples/clean.txt
No findings.
```

That run exits 0. Checking input with a finding exits 1:

```text
$ printf 'mail jane@example.com\n' | python3 pasteguard_cli.py --check
1:6 EMAIL ************.com
```

## Tests

```sh
python3 -m pytest -q
```

Result: 28 passed.

## License

MIT. See LICENSE.
