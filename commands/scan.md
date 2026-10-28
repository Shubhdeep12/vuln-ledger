---
description: Check dependencies for new vulnerabilities and malicious packages; reports only what changed
argument-hint: "[--fresh]"
---

Use the vuln-ledger skill. From the project root, run:

```bash
node "${CLAUDE_PLUGIN_ROOT}/skills/vuln-ledger/scripts/vuln-ledger.mjs" scan $ARGUMENTS
```

Then follow the skill's "Reading the result", "Decide" and "Report and ask"
sections. Report only what changed. Do not update anything without my approval.
