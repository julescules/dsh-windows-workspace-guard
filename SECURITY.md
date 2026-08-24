# Security

## Supported versions

Security fixes are applied to the latest tagged release and current `main`.

## Reporting

Use GitHub private vulnerability reporting when available. Otherwise open a minimal issue without tokens, passwords, private keys, complete environment dumps, credential contents, or real private paths.

Useful reports contain the affected version, a synthetic reproducer, expected and observed decisions, and whether the call reached dispatch.

## Trust boundary

This plugin runs inside the DeepSeek Harness process. It statically inspects configured PowerShell tool arguments and performs bounded filesystem/ACL metadata checks. It is not an operating-system sandbox or general DLP engine. Doctor never reads credential values and never changes ACLs.
