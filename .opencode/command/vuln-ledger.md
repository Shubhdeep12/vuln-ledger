---
{"description": "Check dependencies for vulnerabilities and malicious packages; report only what changed"}
---

Use the `vuln-ledger` skill. Run its `scan` command from the project root and
follow the skill's rules: report only changes since the last check, stop and
ask before updating anything critical, high, exploited, or malicious, and
never update without my approval.
