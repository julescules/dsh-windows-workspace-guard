# dsh-windows-workspace-guard

[中文](README.zh.md) | English

> [!IMPORTANT]
> Unofficial community plugin. Independently developed and maintained; not reviewed or endorsed by DeepSeek.

Safety policy for DeepSeek Harness on Windows. It checks model-issued `pwsh` calls before execution and protects workspaces, original files, and Git history.

![Policy decisions: allow, ask, and hard block](docs/demo.svg)

## What it does

- keeps destructive PowerShell targets inside trusted workspace roots;
- makes `original/`, signing files, or any configured path immutable;
- reviews risky Git commands such as `reset --hard`, `clean -fdx`, and force push;
- supports `block`, one-time `ask`, and audit-only `report` modes;
- writes optional append-only JSONL audit records with redacted previews and command hashes;
- permanently blocks disk operations, broad roots, encoded execution, `System.IO` bypasses, and protected paths.

## Install

```powershell
dsh plugin --profile web add github:julescules/dsh-windows-workspace-guard#v0.2.0
dsh --profile web --dump-config
```

Restart DSH after installation.

## Recommended config

```yaml
- id: windows-workspace-guard
  name: dsh-windows-workspace-guard
  config:
    mode: ask
    workspaceRoots:
      - 'D:\projects\current-project'
    protectedPaths:
      - 'D:\projects\current-project\original'
    guardGit: true
    auditPath: 'D:\projects\current-project\operation_logs\dsh-guard.audit.jsonl'
```

| Result | `block` | `ask` | `report` |
|---|---|---|---|
| Safe | allow | allow | allow |
| Needs review | deny | ask once | allow + audit |
| Hard block | deny | deny | deny |

Hard blocks cannot be bypassed by `allowExact` or report mode.

## Check without running

The plugin registers `windows_workspace_guard_check`. The agent can inspect a command and receive stable `PASS`, `REVIEW`, or `FAIL` JSON without executing it.

## Verified

- 20/20 unit and adversarial tests pass;
- official `dsh.bundle.patch` package shape;
- official `tools/pre-execute` allow/deny/ask contract;
- package contains no install-time build step;
- UTF-8 append-only audit with common secret redaction.

```powershell
npm run check
npm pack --dry-run
```

## Limits

- Static inspection is not a complete PowerShell parser or OS sandbox.
- Only the DSH tool named `pwsh` is intercepted.
- Junction/symlink targets are not resolved against the live filesystem.
- DeepSeek Harness is in developer preview; pin a reviewed release or commit.

## License

[MIT](LICENSE)
