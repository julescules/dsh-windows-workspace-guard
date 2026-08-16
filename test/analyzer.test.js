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
