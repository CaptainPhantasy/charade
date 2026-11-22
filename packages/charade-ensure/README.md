# @floydslabs/charade-ensure

A zero-dependency detection shim for CHARADE. It reports whether a compatible
Charade is present and prints three doors: install, point to an existing instance,
or skip. It never installs anything and never changes another tool's config.

```bash
charade-ensure --json
```

Exit codes: 0 compatible, 10 absent, 11 incompatible, 12 broken, 13 ambiguous.
