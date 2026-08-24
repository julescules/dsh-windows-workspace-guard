# DeepSeek Harness Windows Workspace Guard

中文 | [English](README.md)

[![dshbase verified](https://img.shields.io/badge/dshbase-verified-16a34a)](https://dshbase.com/zh/plugins/dsh-windows-workspace-guard/) [![CI](https://github.com/julescules/dsh-windows-workspace-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/julescules/dsh-windows-workspace-guard/actions/workflows/ci.yml)

> [!IMPORTANT]
> 非官方社区插件，由社区独立开发与维护，未经 DeepSeek 审核或背书。

在 Windows Agent 误删原始文件、越界写盘、破坏 Git 恢复路径、读取凭据或改变系统状态之前阻止它。PowerShell 与官方结构化文件编辑器在分派前都会得到清晰的 **PASS**、**ASK** 或 **HARD BLOCK**。

![合成终端示例：凭据阻断与只读 Doctor](docs/demo.svg)

## 30 秒开始

```powershell
dsh plugin --profile web add github:julescules/dsh-windows-workspace-guard#v0.8.0
dsh --profile web --dump-config
dsh --profile web
```

重启 DSH，然后直接说：

```text
先运行 windows_workspace_guard_doctor，再用 windows_workspace_guard_check
检查下面的命令，但不要执行：
Get-Content -LiteralPath $env:DSH_HOME\.credentials.yaml
```

## v0.8.0 的四个重点

### 已验证的多工具边界

默认同时保护 `pwsh` 与官方 `str_replace_editor`。文件编辑适配器直接读取结构化的 `command` 和 `path` 参数，不把文件内容写入策略预览，并对 `create`、`str_replace`、`insert` 以及敏感路径 `view` 应用工作区、不可变路径、既有链接和凭据规则。

用户配置但没有已验证参数适配器的工具会 fail closed。Doctor 会逐项显示 `covered` 或 `unsupported`，不会把未知参数格式冒充为 PowerShell 后宣称已保护。

升级会保留现有实时设置。如果旧 Profile 已保存 `toolNames: [pwsh]`，请在设置卡中加入 `str_replace_editor`；Doctor 会显示实际生效的覆盖范围。

### 单调强制阻断

工作区越界以及无法可靠验证的变更路径均为硬阻断。`allowExact` 仍可用于明确放行需复核的命令，但不能授权写出工作区，也不能绕过任何不可覆盖策略。

静态不可覆盖规则同时注册到官方同步 `ctx.tools.guard()`。即使另一个可重排的 `tools/pre-execute` 监听器短路 waterfall，这些规则仍保持拒绝。没有该 API 的旧 Harness 版本继续使用 pre-execute 防护。

既有 junction/symlink 检查需要异步访问文件系统，因此仍位于 `tools/pre-execute`，不会冒充同步 guard 能力。

### 凭据与敏感数据边界

默认 `guardSensitiveData: true`，在受保护的 `pwsh(command)` 边界阻断显式读取或复制：

- `$DSH_HOME\.credentials.yaml` 和 `.env` 文件；
- 用户 SSH、AWS、Azure、Git、npm、GitHub CLI、NuGet 凭据位置；
- 用户配置的 `sensitivePaths`；
- 敏感环境变量和完整 `Env:` 枚举；
- 同一命令内将显式敏感来源与网络外传工具组合。

这是保守的工具门禁，不是通用 DLP。它不会检查任意原生进程内存、已经运行的进程，也不会自动保护 `toolNames` 外的工具。

### 只读 Windows Doctor

`windows_workspace_guard_doctor` 只报告事实，不修改 ACL 或配置：

- Host 是否提供 `ctx.tools.guard()`；
- 每个已配置工具的覆盖状态和参数适配器；
- DSH home、工作区根和保护路径状态；
- 配置根目录的链接元数据；
- 审计目录是否可写与有上限的运行时重复副本检查；
- Windows 凭据文件 ACL 元数据，不打开凭据内容。

## 三种判定

| 结果 | 含义 |
|---|---|
| PASS | 当前策略没有匹配到风险。 |
| ASK | 在 `mode: ask` 下，需要 Host 批准一次的可审查操作。 |
| HARD BLOCK | 磁盘/系统变更、策略绕过、不可变路径、链接穿越或敏感数据访问不能靠批准放行。 |

`windows_workspace_guard_check` 是只读 dry-run：`pwsh` 传入命令，`str_replace_editor` 传入操作与绝对路径；它返回机器可读 finding，不执行调用。

## 主要设置

DSH Web 设置卡可以实时修改：

```yaml
enabled: true
mode: block               # block | ask | report
toolNames: [pwsh, str_replace_editor]
workspaceRoots: []        # 空数组表示当前 session cwd
protectedPaths: []
guardExistingLinks: true
guardSensitiveData: true
sensitivePaths: []
auditPath: ''             # 可选追加式 JSONL
auditIncludeCommand: false
auditFailClosed: false
```

配置审计路径后，实际分派的写入发生在 Host 批准和单调 guard 之后；被拒绝的调用在最终结果产生后记录。默认只保存哈希与脱敏预览。

## DSH 集成

插件不修改 Harness 核心，使用官方 `dsh.bundle.patch`、`tools/pre-execute`、`ctx.tools.guard()`、`tools/execute`、`tools/result`、settings 和 typed-tool 接口。

## 升级、禁用、卸载

```powershell
dsh plugin --profile web add github:julescules/dsh-windows-workspace-guard#v0.8.0
dsh plugin --profile web list
dsh plugin --help
```

以当前版本 `dsh plugin --help` 显示的禁用/删除命令为准，然后重启 DSH。Harness 仍处于开发预览，Profile 子命令仍可能变化。

## 排错、权限与数据

- 设置卡不显示：运行 `dsh --profile web --dump-config`，确认出现 `windows-workspace-guard`，再重启 Web。
- 安全命令误判：先运行 dry-run，提交 finding ID 和脱敏命令/路径。
- 插件本身不发起网络请求。Doctor 只读文件系统/ACL 元数据，不读取凭据值。
- 只有配置 `auditPath` 才会创建审计文件。
- `workspaceRoots` 与 `sensitivePaths` 应使用绝对、尽量窄的路径。

## 验证

```powershell
npm run check
npm pack --dry-run
node scripts/build-release-metadata.mjs .\dsh-windows-workspace-guard-0.8.0.tgz .\builds\v0.8.0
.\scripts\verify-release.ps1 -PackagePath .\dsh-windows-workspace-guard-0.8.0.tgz -ChecksumsPath .\builds\v0.8.0\SHA256SUMS
```

每个 Release 同时提供 SHA-256 与 CycloneDX SBOM。验证脚本使用 literal path，且不联网。

## 边界

- 静态策略不等于操作系统沙箱。
- 链接检查到执行之间仍有文件系统 TOCTOU 窗口。
- `toolNames` 外的工具不受保护；已配置但参数模式未知的工具会 fail closed，并在 Doctor 中显示警告。
- ACL 警告只是审查证据，不会自动修复权限。

遇到误报或漏报，请在[官方社区插件帖](https://github.com/deepseek-ai/deepseek-harness/discussions/2429)提供 Windows、PowerShell、DSH 版本、脱敏命令、期望 PASS/ASK/BLOCK 和脱敏 Doctor 输出。

贡献与安全报告见 [CONTRIBUTING.md](CONTRIBUTING.md) 和 [SECURITY.md](SECURITY.md)。

## 许可

[MIT](LICENSE)
