# Changelog

## v1.0.0

- Initial release.
- Detectors for email, US phone, US SSN, Luhn validated credit cards, AWS access keys, GitHub tokens, Slack tokens, private key headers, and JWT shaped tokens.
- CLI flags: file or stdin input, `--json`, `--check`, `--mask` with `--mapping-out`, `--unmask` with `--mapping-in`, and `--report`.
- JSON reports redact values to the last 4 characters.
- 28 pytest tests, all passing.
