# dsh-windows-workspace-guard

[中文](README.zh.md) | English

> [!IMPORTANT]
> Unofficial community plugin. Independently developed and maintained; not reviewed or endorsed by DeepSeek.

Safety policy for DeepSeek Harness on Windows. It checks model-issued PowerShell calls before execution and protects workspaces, original files, persistent shell state, Windows system state, processes, and Git recovery paths.

![Policy decisions: allow, ask, and hard block](docs/demo.svg)

## What it does

- keeps destructive PowerShell targets inside trusted workspace roots;
- makes `original/`, signing files, or any configured path immutable;
- reviews risky Git commands such as `reset --hard`, `clean -fdx`, worktree restore, stash deletion, and force push;
- hard-blocks registry, service, scheduled-task, ACL/ownership, junction/symlink, and nested-shell mutations;
- reviews process termination and supports configurable guarded tool names;
- protects the persistent `pwsh` session added in DSH `v0.1.0-rc.8`: relative mutation targets, command shadowing, dot-sourcing, detached work, remote execution, module state, environment state, and current-directory changes;
- supports `block`, one-time `ask`, and audit-only `report` modes;
- adds a live settings card to the official DSH plugin settings page (DSH `v0.1.0-rc.7` or newer);
- writes optional append-only JSONL audit records with redacted previews and command hashes;
- permanently blocks disk operations, broad roots, encoded execution, `System.IO` bypasses, and protected paths.

## Install

```powershell
dsh plugin --profile web add github:julescules/dsh-windows-workspace-guard#v0.4.0
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
    guardSystem: true
    guardProcesses: true
    guardPersistentShell: true
    requireAbsoluteMutationPaths: true
    auditPath: 'D:\projects\current-project\operation_logs\dsh-guard.audit.jsonl'
```

On DSH `v0.1.0-rc.7` or newer, the same fields can be changed from **Settings → Plugins → Windows Workspace Guard** and apply immediately without restarting the plugin. DSH `v0.1.0-rc.8` or newer is recommended for the persistent Windows PowerShell integration.

`requireAbsoluteMutationPaths` is enabled by default. Read-only commands may still use relative paths, but file deletion, move, copy, rename, and overwrite operations must use drive-qualified or UNC paths. This prevents an earlier persistent `Set-Location` call from changing the meaning of a later command.

| Result | `block` | `ask` | `report` |
|---|---|---|---|
| Safe | allow | allow | allow |
| Needs review | deny | ask once | allow + audit |
| Hard block | deny | deny | deny |

Hard blocks cannot be bypassed by `allowExact` or report mode.

## Check without running

The plugin registers `windows_workspace_guard_check`. The agent can inspect a command and receive stable `PASS`, `REVIEW`, or `FAIL` JSON without executing it.

## Verified

- 34/34 unit, browser-contract, and adversarial tests pass;
- official `dsh.bundle.patch` package shape;
- official keyed `settings.plugin.item` card and `settingsScope` live-config contract;
- official `tools/pre-execute` allow/deny/ask contract;
- real `@deepseek-ai/dsh@0.1.0-rc.8` profile install, config composition, Web Host boot-graph discovery, and served client bundle;
- package contains no install-time build step;
- UTF-8 append-only audit with common secret redaction.

```powershell
npm run check
npm pack --dry-run
```

## Limits

- Static inspection is not a complete PowerShell parser or OS sandbox.
- `pwsh` is intercepted by default; add other PowerShell tool names in `toolNames`.
- Existing junction/symlink targets are not resolved against the live filesystem; creation is hard-blocked.
- The plugin cannot introspect the live PTY current directory, so absolute mutation paths are the default safety boundary.
- DeepSeek Harness is in developer preview; pin a reviewed release or commit.

## License

[MIT](LICENSE)
