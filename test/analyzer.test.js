import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzePowerShellCommand } from '../analyzer.js'

const roots = ['D:\\work\\project']
const options = { cwd: 'D:\\work\\project', workspaceRoots: roots }

test('passes non-destructive commands', () => {
  const result = analyzePowerShellCommand('Get-ChildItem -LiteralPath .', options)
  assert.equal(result.status, 'PASS')
  assert.equal(result.destructive, false)
})

test('passes a literal child deletion inside the workspace', () => {
  const result = analyzePowerShellCommand("Remove-Item -LiteralPath 'D:\\work\\project\\builds\\old' -Recurse", options)
  assert.equal(result.status, 'PASS')
  assert.equal(result.destructive, true)
})

test('blocks -Path because wildcard expansion is possible', () => {
  const result = analyzePowerShellCommand("Remove-Item -Path 'D:\\work\\project\\builds\\*' -Recurse", options)
  assert.equal(result.status, 'FAIL')
  assert.ok(result.findings.some((item) => item.id === 'literal-path-required'))
})

test('does not let one safe literal hide a second unsafe invocation', () => {
  const command = "Remove-Item -LiteralPath 'D:\\work\\project\\safe.tmp'; Remove-Item -Path 'C:\\outside\\*' -Recurse"
  const result = analyzePowerShellCommand(command, options)
  assert.equal(result.status, 'FAIL')
  assert.ok(result.findings.some((item) => item.id === 'literal-path-required'))
})

test('blocks comma-separated destructive target arrays', () => {
  const command = "Remove-Item -LiteralPath 'D:\\work\\project\\safe.tmp', 'C:\\outside\\unsafe.tmp'"
  const result = analyzePowerShellCommand(command, options)
  assert.equal(result.status, 'FAIL')
  assert.ok(result.findings.some((item) => item.id === 'multiple-targets'))
})

test('blocks a drive root', () => {
  const result = analyzePowerShellCommand("Remove-Item -LiteralPath 'D:\\' -Recurse -Force", options)
  assert.equal(result.status, 'FAIL')
  assert.ok(result.findings.some((item) => item.id === 'broad-target'))
})

test('blocks deletion outside configured roots', () => {
  const result = analyzePowerShellCommand("Remove-Item -LiteralPath 'C:\\Users\\Public\\file.txt' -Force", options)
  assert.equal(result.status, 'FAIL')
  assert.ok(result.findings.some((item) => item.id === 'outside-workspace'))
})

test('blocks dynamic and wildcard targets', () => {
  const dynamic = analyzePowerShellCommand("Remove-Item -LiteralPath '$env:USERPROFILE\\*' -Recurse", options)
  assert.equal(dynamic.status, 'FAIL')
  assert.ok(dynamic.findings.some((item) => item.id === 'dynamic-target'))
  assert.ok(dynamic.findings.some((item) => item.id === 'wildcard-target'))
})

test('validates both Move-Item source and destination', () => {
  const safe = analyzePowerShellCommand("Move-Item -LiteralPath 'D:\\work\\project\\a' -Destination 'D:\\work\\project\\archive\\a'", options)
  assert.equal(safe.status, 'PASS')

  const unsafe = analyzePowerShellCommand("Move-Item -LiteralPath 'D:\\work\\project\\a' -Destination 'C:\\archive\\a'", options)
  assert.equal(unsafe.status, 'FAIL')
  assert.ok(unsafe.findings.some((item) => item.id === 'outside-workspace'))
})

test('blocks disk, cmd, .NET, and robocopy bypass families', () => {
  const commands = [
    'Format-Volume -DriveLetter D',
    'cmd /c rd /s /q D:\\work\\project',
    "[System.IO.Directory]::Delete('D:\\work\\project', $true)",
    'robocopy D:\\empty D:\\work\\project /MIR',
  ]
  for (const command of commands) {
    assert.equal(analyzePowerShellCommand(command, options).status, 'FAIL', command)
  }
})

test('exact allowlist is explicit and deterministic', () => {
  const command = "Remove-Item -LiteralPath 'C:\\outside\\known.tmp' -Force"
  const result = analyzePowerShellCommand(command, { ...options, allowExact: [command] })
  assert.equal(result.status, 'PASS')
  assert.equal(result.allowedByExact, true)
})

test('protects immutable source media even inside the workspace', () => {
  const command = "Remove-Item -LiteralPath 'D:\\work\\project\\original\\master.zip' -Force"
  const result = analyzePowerShellCommand(command, { ...options, protectedPaths: ['D:\\work\\project\\original'] })
  assert.equal(result.status, 'FAIL')
  assert.equal(result.hardBlock, true)
  assert.ok(result.findings.some((item) => item.id === 'protected-path'))
})

test('exact allowlist cannot bypass non-overridable policy', () => {
  const protectedCommand = "Remove-Item -LiteralPath 'D:\\work\\project\\original\\master.zip' -Force"
  const protectedResult = analyzePowerShellCommand(protectedCommand, {
    ...options,
    protectedPaths: ['D:\\work\\project\\original'],
    allowExact: [protectedCommand],
  })
  assert.equal(protectedResult.status, 'FAIL')
  assert.equal(protectedResult.hardBlock, true)

  const diskCommand = 'Format-Volume -DriveLetter D'
  const diskResult = analyzePowerShellCommand(diskCommand, { ...options, allowExact: [diskCommand] })
  assert.equal(diskResult.status, 'FAIL')
  assert.equal(diskResult.hardBlock, true)
})

test('reviews dangerous Git history and cleanup commands', () => {
  const forcePush = analyzePowerShellCommand('git push origin main --force-with-lease', options)
  assert.equal(forcePush.status, 'REVIEW')
  assert.ok(forcePush.findings.some((item) => item.id === 'git-force-push'))

  const hardReset = analyzePowerShellCommand('git reset --hard HEAD~1', options)
  assert.equal(hardReset.status, 'REVIEW')
  assert.equal(hardReset.risk, 'CRITICAL')
})

test('reviews additional Git operations that discard recovery state', () => {
  const commands = [
    ['git clean -fdx', 'git-clean-force'],
    ['git restore src/app.js', 'git-restore-worktree'],
    ['git checkout HEAD -- src/app.js', 'git-checkout-paths'],
    ['git stash drop stash@{0}', 'git-stash-delete'],
    ['git stash clear', 'git-stash-delete'],
    ['git worktree remove D:\\work\\old --force', 'git-worktree-remove'],
    ['git update-ref -d refs/heads/old', 'git-update-ref-delete'],
  ]
  for (const [command, id] of commands) {
    const result = analyzePowerShellCommand(command, options)
    assert.equal(result.status, 'REVIEW', command)
    assert.ok(result.findings.some((item) => item.id === id), command)
  }

  const stagedOnly = analyzePowerShellCommand('git restore --staged src/app.js', options)
  assert.equal(stagedOnly.status, 'PASS')
})

test('hard-blocks opaque nested PowerShell execution', () => {
  const result = analyzePowerShellCommand('pwsh.exe -NoProfile -Command "Remove-Item C:\\outside"', options)
  assert.equal(result.status, 'FAIL')
  assert.equal(result.hardBlock, true)
  assert.ok(result.findings.some((item) => item.id === 'nested-shell'))
})

test('hard-blocks Windows system mutation families', () => {
  const commands = [
    ["Set-ItemProperty -LiteralPath 'HKLM:\\Software\\Example' -Name Enabled -Value 1", 'registry-mutation'],
    ["Set-Item -LiteralPath 'HKCU:\\Software\\Example' -Value unsafe", 'registry-mutation'],
    ["Set-Service -Name Spooler -StartupType Disabled", 'service-mutation'],
    ["Disable-ScheduledTask -TaskName Example", 'scheduled-task-mutation'],
    ["icacls.exe D:\\work\\project /grant Users:F", 'acl-mutation'],
    ["New-Item -ItemType Junction -Path D:\\work\\project\\link -Target C:\\outside", 'reparse-mutation'],
  ]
  for (const [command, id] of commands) {
    const result = analyzePowerShellCommand(command, options)
    assert.equal(result.status, 'FAIL', command)
    assert.equal(result.hardBlock, true, command)
    assert.ok(result.findings.some((item) => item.id === id), command)
  }
})

test('makes system and process guards independently configurable', () => {
  const systemOff = analyzePowerShellCommand('Stop-Service -Name Spooler', { ...options, guardSystem: false })
  assert.equal(systemOff.status, 'PASS')

  const process = analyzePowerShellCommand('Stop-Process -Name notepad', options)
  assert.equal(process.status, 'REVIEW')
  assert.ok(process.findings.some((item) => item.id === 'process-termination'))

  const processOff = analyzePowerShellCommand('Stop-Process -Name notepad', { ...options, guardProcesses: false })
  assert.equal(processOff.status, 'PASS')
})

test('requires absolute mutation paths for persistent PowerShell safety', () => {
  const relative = analyzePowerShellCommand("Remove-Item -LiteralPath '.\\builds\\old' -Recurse", options)
  assert.equal(relative.status, 'FAIL')
  assert.equal(relative.hardBlock, true)
  assert.ok(relative.findings.some((item) => item.id === 'relative-target'))

  const legacy = analyzePowerShellCommand(
    "Remove-Item -LiteralPath '.\\builds\\old' -Recurse",
    { ...options, requireAbsoluteMutationPaths: false },
  )
  assert.equal(legacy.status, 'PASS')
})

test('does not trust the startup cwd after a persistent location change', () => {
  const result = analyzePowerShellCommand(
    "Set-Location 'C:\\outside'; Remove-Item -LiteralPath '.\\victim.txt' -Force",
    options,
  )
  assert.equal(result.status, 'FAIL')
  assert.ok(result.findings.some((item) => item.id === 'persistent-cwd-change'))
  assert.ok(result.findings.some((item) => item.id === 'relative-target'))

  const locationOnly = analyzePowerShellCommand("Set-Location 'D:\\work\\project\\src'", options)
  assert.equal(locationOnly.status, 'REVIEW')
})

test('hard-blocks persistent command-resolution bypasses', () => {
  const commands = [
    ["Set-Alias -Name Remove-Item -Value Invoke-Expression", 'command-shadowing'],
    ["sal Remove-Item Invoke-Expression", 'command-shadowing'],
    ["function global:Remove-Item { param($x) cmd /c del $x }", 'command-shadowing'],
    [". '.\\bootstrap.ps1'", 'dot-source'],
    ["Invoke-Command -ComputerName host -ScriptBlock { whoami }", 'remote-execution'],
    ["icm host { whoami }", 'remote-execution'],
  ]
  for (const [command, id] of commands) {
    const result = analyzePowerShellCommand(command, options)
    assert.equal(result.status, 'FAIL', command)
    assert.equal(result.hardBlock, true, command)
    assert.ok(result.findings.some((item) => item.id === id), command)
  }
})

test('hard-blocks detached work that can outlive the inspected call', () => {
  for (const command of [
    "Start-Process pwsh -ArgumentList '-Command', 'Remove-Item C:\\outside'",
    "Start-Job -ScriptBlock { Remove-Item C:\\outside }",
    "saps pwsh -ArgumentList '-Command', 'whoami'",
    "Register-EngineEvent PowerShell.Exiting -Action { Set-Content C:\\outside\\x 1 }",
  ]) {
    const result = analyzePowerShellCommand(command, options)
    assert.equal(result.status, 'FAIL', command)
    assert.ok(result.findings.some((item) => item.id === 'detached-execution'), command)
  }
})

test('reviews persistent module and environment state', () => {
  const moduleState = analyzePowerShellCommand('Import-Module ExampleTools', options)
  assert.equal(moduleState.status, 'REVIEW')
  assert.ok(moduleState.findings.some((item) => item.id === 'module-state'))

  const addType = analyzePowerShellCommand("Add-Type -TypeDefinition 'public class X {}'", options)
  assert.equal(addType.status, 'REVIEW')
  assert.ok(addType.findings.some((item) => item.id === 'module-state'))

  const environment = analyzePowerShellCommand("$env:EXAMPLE_MODE='unsafe'", options)
  assert.equal(environment.status, 'REVIEW')
  assert.ok(environment.findings.some((item) => item.id === 'persistent-environment'))

  const readAfterEnvironment = analyzePowerShellCommand("$env:EXAMPLE_MODE='unsafe'; Get-Content -LiteralPath '.\\config.txt'", options)
  assert.equal(readAfterEnvironment.status, 'REVIEW')
  assert.ok(!readAfterEnvironment.findings.some((item) => item.id === 'relative-target'))

  const disabled = analyzePowerShellCommand('Import-Module ExampleTools', { ...options, guardPersistentShell: false })
  assert.equal(disabled.status, 'PASS')
})

test('hard-blocks Win32 device namespace targets', () => {
  const result = analyzePowerShellCommand("Remove-Item -LiteralPath '\\\\?\\C:\\outside\\victim.txt'", options)
  assert.equal(result.status, 'FAIL')
  assert.ok(result.findings.some((item) => item.id === 'device-path'))
})

test('checks overwrite-capable cmdlets and copy destinations', () => {
  const writeOutside = analyzePowerShellCommand("Set-Content -LiteralPath 'C:\\outside\\config.txt' -Value x", options)
  assert.equal(writeOutside.status, 'FAIL')
  assert.equal(writeOutside.mutating, true)

  const copyProtected = analyzePowerShellCommand(
    "Copy-Item -LiteralPath 'D:\\work\\project\\build\\a.bin' -Destination 'D:\\work\\project\\original\\a.bin' -Force",
    { ...options, protectedPaths: ['D:\\work\\project\\original'] },
  )
  assert.equal(copyProtected.status, 'FAIL')
  assert.ok(copyProtected.findings.some((item) => item.id === 'protected-path'))
})

test('redacts common secrets from previews', () => {
  const result = analyzePowerShellCommand("Set-Content -LiteralPath 'D:\\work\\project\\x' -Value x; $env:API_TOKEN='super-secret'", options)
  assert.doesNotMatch(result.commandPreview, /super-secret/)
  assert.match(result.commandPreview, /\[REDACTED\]/)
})
