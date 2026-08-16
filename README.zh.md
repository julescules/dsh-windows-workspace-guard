# dsh-windows-workspace-guard

中文 | [English](README.md)

> [!IMPORTANT]
> 非官方社区插件，由社区成员独立开发和维护，未经 DeepSeek 官方审核或背书。

这是一个面向 Windows 的 DeepSeek Harness 安全插件。它会在执行前检查 Agent 发出的 `pwsh` 命令，保护工作区、原始文件和 Git 历史。

![允许、审批和强制阻断三种策略结果](docs/demo.svg)

## 能做什么

- 删除、移动和覆盖目标必须位于可信工作区内；
- 可将 `original/`、签名文件或任意目录设为不可修改；
- 检查 `git reset --hard`、`git clean -fdx`、强推等高风险操作；
- 支持直接阻断、单次审批、只记录不阻断三种模式；
- 可写入追加式 JSONL 审计，命令预览会脱敏并保存 SHA-256；
- 磁盘操作、盘符根目录、编码命令、`System.IO` 绕过和保护目录始终强制阻断。

## 安装

```powershell
dsh plugin --profile web add github:julescules/dsh-windows-workspace-guard#v0.2.0
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
    auditPath: 'D:\projects\current-project\operation_logs\dsh-guard.audit.jsonl'
```

| 检查结果 | `block` | `ask` | `report` |
|---|---|---|---|
| 安全 | 放行 | 放行 | 放行 |
| 需要复核 | 阻断 | 请求单次批准 | 放行并记录 |
| 强制阻断 | 阻断 | 阻断 | 阻断 |

强制阻断不能被 `allowExact` 或 `report` 模式绕过。

## 执行前自检

插件注册了 `windows_workspace_guard_check`。Agent 可以先检查命令，获得稳定的 `PASS`、`REVIEW` 或 `FAIL` JSON，而不会执行命令。

## 已验证

- 20/20 单元及对抗测试通过；
- 使用官方 `dsh.bundle.patch` 插件结构；
- 使用官方 `tools/pre-execute` allow/deny/ask 协议；
- 安装时不需要运行构建脚本；
- UTF-8 追加式审计及常见密钥脱敏。

```powershell
npm run check
npm pack --dry-run
```

## 已知限制

- 静态检查不能代替完整 PowerShell 解析器或操作系统沙箱；
- 只拦截名称为 `pwsh` 的 DSH 工具；
- 目前不会在运行时解析 junction/symlink；
- DeepSeek Harness 仍处于开发预览阶段，建议固定已审核的版本或提交。

## 许可证

[MIT](LICENSE)
