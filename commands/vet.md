---
description: Check a package before installing it (malicious, vulnerable, non-existent, too new)
argument-hint: "<eco:name[@version]> ...  e.g. npm:express@4.21.2 composer:vendor/pkg pypi:requests"
---

Use the vuln-ledger skill. If no package was given, ask which one and stop.
Otherwise, from the project root, run:

```bash
node "${CLAUDE_PLUGIN_ROOT}/skills/vuln-ledger/scripts/vuln-ledger.mjs" vet $ARGUMENTS
```

Give the verdict for each package (BLOCK, CAUTION, OK) with the reason, as in
the skill's "Adding a package" section. Do not install anything.
