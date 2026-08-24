# Contributing

Contributions should address a reproducible Windows/PowerShell safety case and keep policy deterministic, inspectable, and compatible with official DeepSeek Harness plugin seams.

Before opening a pull request:

1. Separate observed behavior, inference, and unresolved questions.
2. Add a focused test with synthetic paths and redacted values.
3. Keep hard blocks narrow and explain false-positive tradeoffs.
4. Do not add network calls, credential contents, personal paths, destructive fixtures, or automatic ACL repair.
5. Run `npm run check` and `npm pack --dry-run`.

For an incorrect decision, include Windows, PowerShell and DSH versions, finding IDs, a redacted command, and expected PASS/ASK/BLOCK.
