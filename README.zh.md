# dsh-windows-workspace-guard

中文 | [English](README.md)

> [!IMPORTANT]
> 非官方社区插件，由社区成员独立开发和维护，未经 DeepSeek 官方审核或背书。

这是一个面向 Windows 的 DeepSeek Harness 安全插件。它会在执行前检查 Agent 发出的 PowerShell 命令，保护工作区、原始文件、持久 Shell 状态、Windows 系统状态、进程和 Git 恢复路径。

![允许、审批和强制阻断三种策略结果](docs/demo.svg)

## 能做什么

- 删除、移动和覆盖目标必须位于可信工作区内；
- 可将 `original/`、签名文件或任意目录设为不可修改；
- 检查 `git reset --hard`、`git clean -fdx`、工作树还原、删除 stash、强推等高风险操作；
- 强制阻断注册表、WMI/CIM、服务、计划任务、ACL/所有权、junction/symlink/hardlink、NTFS 备用数据流和嵌套 PowerShell 变更；
- 检查 `Out-File`、`Tee-Object`、导出命令以及 `>`/`>>` 的输出目标是否位于可信工作区；
- 默认阻断原生 Shell／脚本宿主逃逸和下载落盘绕过；
- 检查终止进程操作，并可配置需要拦截的工具名称；
- 适配 DSH `v0.1.0-rc.8` 新增的持久 `pwsh`：防护相对变更路径、命令遮蔽、dot-source、脱离式任务、远程执行、模块、环境变量和当前目录状态；
- 支持直接阻断、单次审批、只记录不阻断三种模式；
- 在官方 DSH 插件设置页提供实时设置卡片（需要 DSH `v0.1.0-rc.7` 或更新版本）；
- 可写入追加式 JSONL 审计，命令预览会脱敏并保存 SHA-256；
- 磁盘操作、盘符根目录、编码命令、`System.IO` 绕过和保护目录始终强制阻断。

## 安装

```powershell
dsh plugin --profile web add github:julescules/dsh-windows-workspace-guard#v0.5.0
dsh --profile web --dump-config
```

安装后重新启动 DSH。

## 推荐配置

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
    guardNativeEscapes: true
    guardPersistentShell: true
    requireAbsoluteMutationPaths: true
    auditPath: 'D:\projects\current-project\operation_logs\dsh-guard.audit.jsonl'
```

在 DSH `v0.1.0-rc.7` 或更新版本中，也可以从“设置 → 插件 → Windows 工作区防护”修改这些字段，保存后立即生效，不需要重启插件。本版本已针对 DSH `v0.1.1-rc.2` 验证，并保留 rc.8 引入的持久 PowerShell 契约。

`requireAbsoluteMutationPaths` 默认启用。只读命令仍可使用相对路径，但删除、移动、复制、重命名和覆盖文件时必须使用带盘符的绝对路径或 UNC 路径，防止之前的持久 `Set-Location` 改变后续命令的真实目标。

| 检查结果 | `block` | `ask` | `report` |
|---|---|---|---|
| 安全 | 放行 | 放行 | 放行 |
| 需要复核 | 阻断 | 请求单次批准 | 放行并记录 |
| 强制阻断 | 阻断 | 阻断 | 阻断 |

强制阻断不能被 `allowExact` 或 `report` 模式绕过。

## 执行前自检

插件注册了 `windows_workspace_guard_check`。Agent 可以先检查命令，获得稳定的 `PASS`、`REVIEW` 或 `FAIL` JSON，而不会执行命令。

## 已验证

- 38/38 单元、浏览器接口及对抗测试通过；
- 使用官方 `dsh.bundle.patch` 插件结构；
- 使用官方带 key 的 `settings.plugin.item` 设置卡及 `settingsScope` 实时配置协议；
- 使用官方 `tools/pre-execute` allow/deny/ask 协议；
- 已通过真实 `@deepseek-ai/dsh@0.1.1-rc.2` Profile 安装、配置组合、Web Host 启动图发现及客户端 bundle 服务验证；
- 安装时不需要运行构建脚本；
- UTF-8 追加式审计及常见密钥脱敏。

```powershell
npm run check
npm pack --dry-run
```

## 已知限制

- 静态检查不能代替完整 PowerShell 解析器或操作系统沙箱；
- 默认拦截 `pwsh`；可在 `toolNames` 中加入其他 PowerShell 工具名称；
- 目前不会在运行时解析既有 junction/symlink，但会强制阻断创建操作；
- 插件无法直接读取 PTY 的实时当前目录，因此默认以“变更操作必须使用绝对路径”作为安全边界；
- DeepSeek Harness 仍处于开发预览阶段，建议固定已审核的版本或提交。

## 许可证

[MIT](LICENSE)
