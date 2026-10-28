---
description: Show open findings and accepted risks from the ledger (no network)
argument-hint: "[--all]"
---

Use the vuln-ledger skill. From the project root, run:

```bash
node "${CLAUDE_PLUGIN_ROOT}/skills/vuln-ledger/scripts/vuln-ledger.mjs" status $ARGUMENTS
```

Show what is still open, most severe first, and any accepted risks with their
expiry. Keep it short. Do not update or accept anything.
