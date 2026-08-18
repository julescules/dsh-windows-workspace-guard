import path from 'node:path'

export const POLICY_VERSION = '2026-08-18.3'

const POWERSHELL_MUTATION_PATTERN = /\b(?:Remove-Item|Move-Item|Clear-Content|Rename-Item|Copy-Item|Set-Content|ri|rm|del|erase|rmdir|rd|mi|mv|ren|cp|copy)\b/i
const DESTRUCTIVE_PATTERN = /\b(?:Remove-Item|Move-Item|Clear-Content|Rename-Item|ri|rm|del|erase|rmdir|rd|mi|mv|ren)\b/i
const DISK_PATTERN = /\b(?:Format-Volume|Clear-Disk|Initialize-Disk|Remove-Partition|Remove-Volume|diskpart)\b/i
const DOTNET_MUTATION_PATTERN = /\[(?:System\.)?IO\.(?:Directory|File)\]\s*::\s*(?:Delete|Move|WriteAllText|WriteAllBytes|Create)\s*\(/i
const CMD_DELETE_PATTERN = /\b(?:cmd(?:\.exe)?\s*\/c\s+)?(?:rd|rmdir|del|erase)\b/i
const ROBOCOPY_MIRROR_PATTERN = /\brobocopy\b[^\r\n]*(?:\/MIR|\/PURGE)\b/i
const OPAQUE_EXECUTION_PATTERN = /\b(?:Invoke-Expression|iex|EncodedCommand|enc)\b/i
const NESTED_SHELL_PATTERN = /\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*(?:-(?:Command|EncodedCommand)|\s-enc\b)/i
const REGISTRY_MUTATION_PATTERN = /(?:\b(?:New|Set|Remove|Rename)-ItemProperty\b[^\r\n]*(?:Registry::|HK(?:LM|CU|CR|U|CC):)|\breg(?:\.exe)?\s+(?:add|delete|import|restore|load|unload|copy)\b)/i
const SERVICE_MUTATION_PATTERN = /(?:\b(?:New|Set|Remove|Start|Stop|Restart)-Service\b|\bsc(?:\.exe)?\s+(?:create|delete|config|start|stop|failure|sidtype|privs)\b)/i
const SCHEDULED_TASK_MUTATION_PATTERN = /(?:\b(?:Register|Unregister|Set|Start|Stop|Disable|Enable)-ScheduledTask\b|\bschtasks(?:\.exe)?\s+\/(?:create|delete|change|run|end)\b)/i
const ACL_MUTATION_PATTERN = /(?:\bSet-Acl\b|\btakeown(?:\.exe)?\b|\bicacls(?:\.exe)?\b[^\r\n]*\/(?:grant|deny|remove|setowner|reset|inheritance|restore)\b)/i
const REPARSE_MUTATION_PATTERN = /(?:\bNew-Item\b[^\r\n]*-ItemType\s+(?:SymbolicLink|Junction)|\bmklink\b)/i
const PROCESS_TERMINATION_PATTERN = /(?:\bStop-Process\b|\btaskkill(?:\.exe)?\b)/i
const LITERAL_PATH_PATTERN = /-LiteralPath\s+(?:'([^']*)'|"([^"]*)"|([^\s;|&]+))/gi
const DESTINATION_PATTERN = /-Destination\s+(?:'([^']*)'|"([^"]*)"|([^\s;|&]+))/gi
const PATH_PATTERN = /-Path\s+(?:'([^']*)'|"([^"]*)"|([^\s;|&]+))/gi

const HARD_BLOCK_IDS = new Set([
  'disk-mutation',
  'dotnet-bypass',
  'cmd-bypass',
  'mirror-delete',
  'opaque-execution',
  'nested-shell',
  'registry-mutation',
  'service-mutation',
  'scheduled-task-mutation',
  'acl-mutation',
  'reparse-mutation',
  'protected-path',
  'broad-target',
])

function finding(id, severity, message, evidence = '') {
  return { id, severity, message, evidence, hardBlock: HARD_BLOCK_IDS.has(id) }
}

export function redactCommand(command) {
  return command
    .replace(/((?:api[_-]?key|token|password|passwd|secret|credential)\s*(?:=|:)\s*)(?:'[^']*'|"[^"]*"|[^\s;]+)/gi, '$1[REDACTED]')
    .replace(/(\$env:[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)\s*=\s*)(?:'[^']*'|"[^"]*"|[^\s;]+)/gi, '$1[REDACTED]')
}

function compactCommand(command) {
  const oneLine = redactCommand(command).replace(/\s+/g, ' ').trim()
  return oneLine.length > 180 ? `${oneLine.slice(0, 179)}…` : oneLine
}

function collectValues(pattern, command) {
  const values = []
  pattern.lastIndex = 0
  let match
  while ((match = pattern.exec(command)) !== null) values.push(match[1] ?? match[2] ?? match[3] ?? '')
  return values
}

function countMatches(pattern, command) {
  const flags = pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`
  return [...command.matchAll(new RegExp(pattern.source, flags))].length
}

export function normalizeWindowsPath(value, cwd) {
  return path.win32.resolve(cwd, value).replace(/[\\/]+$/, '')
}

function isDriveOrShareRoot(value) {
  const normalized = value.replace(/\//g, '\\')
  return /^[A-Za-z]:\\?$/.test(normalized) || /^\\\\[^\\]+\\[^\\]+\\?$/.test(normalized)
}

export function isInsideOrEqual(candidate, root) {
  const normalizedCandidate = normalizeWindowsPath(candidate, root).toLowerCase()
  const normalizedRoot = normalizeWindowsPath(root, root).toLowerCase()
  return normalizedCandidate === normalizedRoot || normalizedCandidate.startsWith(`${normalizedRoot}\\`)
}

function validateTarget(value, cwd, roots, protectedPaths, role) {
  const findings = []
  if (!value) return [finding('empty-target', 'FAIL', `${role} target is empty.`)]
  if (/\$\(|`|\$\{|\$env:|\$HOME|^~(?:[\\/]|$)/i.test(value)) {
    findings.push(finding('dynamic-target', 'FAIL', `${role} target is dynamic and cannot be proven safe.`, value))
  }
  if (/[*?\[]/.test(value)) findings.push(finding('wildcard-target', 'FAIL', `${role} target contains a wildcard.`, value))
  if (/^(?:\.|\.\.|[\\/])$/.test(value) || isDriveOrShareRoot(value)) {
    findings.push(finding('broad-target', 'CRITICAL', `${role} target is a workspace, drive, or share root.`, value))
  }
  if (findings.length > 0) return findings

  const resolved = normalizeWindowsPath(value, cwd)
  const protectedMatch = protectedPaths.find((protectedPath) => isInsideOrEqual(resolved, protectedPath))
  if (protectedMatch) findings.push(finding('protected-path', 'CRITICAL', `${role} target is inside an immutable protected path.`, resolved))
  if (roots.length === 0) {
    findings.push(finding('missing-workspace-root', 'FAIL', `No trusted workspace root is available for ${role.toLowerCase()} validation.`, resolved))
  } else {
    const equalRoot = roots.some((root) => normalizeWindowsPath(resolved, cwd).toLowerCase() === normalizeWindowsPath(root, cwd).toLowerCase())
    if (equalRoot || !roots.some((root) => isInsideOrEqual(resolved, root))) {
      findings.push(finding('outside-workspace', 'FAIL', `${role} target is outside a trusted workspace child path or equals the workspace root.`, resolved))
    }
  }
  return findings
}

function analyzeGit(command) {
  if (!/\bgit(?:\.exe)?\b/i.test(command)) return []
  const rules = [
    ['git-reset-hard', /\bgit(?:\.exe)?\b[^\r\n;&|]*\breset\b[^\r\n;&|]*--hard\b/i, 'CRITICAL', 'git reset --hard can discard tracked changes.'],
    ['git-clean-force', /\bgit(?:\.exe)?\b[^\r\n;&|]*\bclean\b[^\r\n;&|]*(?:--force\b|-(?=[a-z]*f)[a-z]+\b)/i, 'CRITICAL', 'git clean with force can permanently remove untracked work.'],
    ['git-force-push', /\bgit(?:\.exe)?\b[^\r\n;&|]*\bpush\b[^\r\n;&|]*(?:--force(?:-with-lease)?|-f)\b/i, 'HIGH', 'Force-pushing can rewrite shared remote history.'],
    ['git-branch-delete', /\bgit(?:\.exe)?\b[^\r\n;&|]*\bbranch\b[^\r\n;&|]*\s-D(?:\s|$)/i, 'HIGH', 'Force-deleting a branch can discard its reachable name.'],
    ['git-reflog-expire', /\bgit(?:\.exe)?\b[^\r\n;&|]*\breflog\s+expire\b/i, 'HIGH', 'Expiring reflogs removes a recovery path.'],
    ['git-prune-now', /\bgit(?:\.exe)?\b[^\r\n;&|]*\bgc\b[^\r\n;&|]*--prune(?:=|\s+)now\b/i, 'HIGH', 'Immediate Git pruning removes recovery objects.'],
    ['git-restore-worktree', /\bgit(?:\.exe)?\b[^\r\n;&|]*\brestore\b(?![^\r\n;&|]*--staged\b)[^\r\n;&|]*/i, 'HIGH', 'git restore can overwrite uncommitted worktree changes.'],
    ['git-checkout-paths', /\bgit(?:\.exe)?\b[^\r\n;&|]*\bcheckout\b[^\r\n;&|]*\s--\s/i, 'HIGH', 'git checkout -- can overwrite uncommitted paths.'],
    ['git-stash-delete', /\bgit(?:\.exe)?\b[^\r\n;&|]*\bstash\s+(?:drop|clear)\b/i, 'HIGH', 'Deleting stashes removes a recovery path.'],
    ['git-worktree-remove', /\bgit(?:\.exe)?\b[^\r\n;&|]*\bworktree\s+remove\b[^\r\n;&|]*(?:--force|-f)\b/i, 'HIGH', 'Force-removing a worktree can discard uncommitted files.'],
    ['git-update-ref-delete', /\bgit(?:\.exe)?\b[^\r\n;&|]*\bupdate-ref\b[^\r\n;&|]*\s-d\b/i, 'HIGH', 'Deleting a ref can remove a recovery name.'],
  ]
  return rules.filter(([, pattern]) => pattern.test(command)).map(([id, , severity, message]) => finding(id, severity, message))
}

function maxRisk(findings) {
  const order = { LOW: 0, MEDIUM: 1, HIGH: 2, FAIL: 3, CRITICAL: 4 }
  return findings.reduce((risk, item) => order[item.severity] > order[risk] ? item.severity : risk, 'LOW')
}

export function analyzePowerShellCommand(command, options = {}) {
  const text = typeof command === 'string' ? command : ''
  const cwd = typeof options.cwd === 'string' && options.cwd.trim() ? options.cwd : process.cwd()
  const roots = Array.isArray(options.workspaceRoots)
    ? options.workspaceRoots.filter((value) => typeof value === 'string' && value.trim()).map((value) => normalizeWindowsPath(value, cwd))
    : []
  const protectedPaths = Array.isArray(options.protectedPaths)
    ? options.protectedPaths.filter((value) => typeof value === 'string' && value.trim()).map((value) => normalizeWindowsPath(value, cwd))
    : []
  const allowExact = new Set(Array.isArray(options.allowExact) ? options.allowExact : [])
  const findings = []

  if (!text.trim()) {
    return { policyVersion: POLICY_VERSION, status: 'PASS', risk: 'LOW', mutating: false, destructive: false, hardBlock: false, allowedByExact: false, commandPreview: '', targets: [], findings: [] }
  }

  const diskMutation = DISK_PATTERN.test(text)
  const dotnetMutation = DOTNET_MUTATION_PATTERN.test(text)
  const cmdMutation = CMD_DELETE_PATTERN.test(text)
  const mirrorMutation = ROBOCOPY_MIRROR_PATTERN.test(text)
  const opaqueExecution = OPAQUE_EXECUTION_PATTERN.test(text)
  const nestedShell = NESTED_SHELL_PATTERN.test(text)
  const cmdletMutation = POWERSHELL_MUTATION_PATTERN.test(text)
  const destructive = diskMutation || dotnetMutation || cmdMutation || mirrorMutation || DESTRUCTIVE_PATTERN.test(text)
  const gitFindings = options.guardGit === false ? [] : analyzeGit(text)
  const systemFindings = options.guardSystem === false ? [] : [
    REGISTRY_MUTATION_PATTERN.test(text) ? finding('registry-mutation', 'CRITICAL', 'Registry mutation is outside the file-workspace safety boundary.') : undefined,
    SERVICE_MUTATION_PATTERN.test(text) ? finding('service-mutation', 'CRITICAL', 'Service mutation can persist or disrupt system-wide execution.') : undefined,
    SCHEDULED_TASK_MUTATION_PATTERN.test(text) ? finding('scheduled-task-mutation', 'CRITICAL', 'Scheduled-task mutation creates persistence outside the workspace.') : undefined,
    ACL_MUTATION_PATTERN.test(text) ? finding('acl-mutation', 'CRITICAL', 'ACL or ownership mutation can bypass workspace access controls.') : undefined,
    REPARSE_MUTATION_PATTERN.test(text) ? finding('reparse-mutation', 'CRITICAL', 'Symbolic-link or junction creation can redirect later writes outside the workspace.') : undefined,
  ].filter(Boolean)
  const processFindings = options.guardProcesses === false || !PROCESS_TERMINATION_PATTERN.test(text)
    ? []
    : [finding('process-termination', 'HIGH', 'Process termination can kill the Harness, a service, or unrelated user work.')]
  const mutating = destructive || cmdletMutation || gitFindings.length > 0 || systemFindings.length > 0 || processFindings.length > 0 || opaqueExecution || nestedShell

  if (!mutating) {
    return { policyVersion: POLICY_VERSION, status: 'PASS', risk: 'LOW', mutating: false, destructive: false, hardBlock: false, allowedByExact: false, commandPreview: compactCommand(text), targets: [], findings: [] }
  }

  if (diskMutation) findings.push(finding('disk-mutation', 'CRITICAL', 'Disk and volume mutation is outside the safe workspace model.'))
  if (dotnetMutation) findings.push(finding('dotnet-bypass', 'CRITICAL', 'Direct System.IO mutation bypasses the PowerShell cmdlet path contract.'))
  if (cmdMutation) findings.push(finding('cmd-bypass', 'CRITICAL', 'cmd.exe deletion aliases bypass -LiteralPath validation.'))
  if (mirrorMutation) findings.push(finding('mirror-delete', 'CRITICAL', 'robocopy mirror or purge can delete destination content.'))
  if (opaqueExecution) findings.push(finding('opaque-execution', 'CRITICAL', 'Encoded or dynamically evaluated PowerShell cannot be statically proven safe.'))
  if (nestedShell) findings.push(finding('nested-shell', 'CRITICAL', 'Nested PowerShell command execution hides the effective command from this policy boundary.'))
  findings.push(...gitFindings)
  findings.push(...systemFindings)
  findings.push(...processFindings)

  const targets = collectValues(LITERAL_PATH_PATTERN, text)
  const pathTargets = collectValues(PATH_PATTERN, text)
  const cmdletMutationCount = countMatches(POWERSHELL_MUTATION_PATTERN, text)
  if (cmdletMutation && targets.length < cmdletMutationCount) {
    findings.push(finding('literal-path-required', 'FAIL', 'Every mutating PowerShell cmdlet must use an explicit -LiteralPath target.'))
  }
  if (pathTargets.length > 0) findings.push(finding('path-expansion', 'FAIL', 'Mutating -Path arguments allow wildcard expansion; use -LiteralPath.', pathTargets.join(', ')))
  if (/-LiteralPath\s+(?:'[^']*'|"[^"]*"|[^\s;|&]+)\s*,/i.test(text)) {
    findings.push(finding('multiple-targets', 'FAIL', 'Comma-separated mutation targets are ambiguous; use one explicit invocation per target.'))
  }
  for (const target of targets) findings.push(...validateTarget(target, cwd, roots, protectedPaths, 'Source'))

  if (/\b(?:Move-Item|Copy-Item|mi|mv|cp|copy)\b/i.test(text)) {
    const destinationCount = countMatches(/\b(?:Move-Item|Copy-Item|mi|mv|cp|copy)\b/i, text)
    const destinations = collectValues(DESTINATION_PATTERN, text)
    if (destinations.length < destinationCount) findings.push(finding('destination-required', 'FAIL', 'Every move/copy invocation must use an explicit -Destination target.'))
    for (const destination of destinations) findings.push(...validateTarget(destination, cwd, roots, protectedPaths, 'Destination'))
    targets.push(...destinations)
  }

  let unique = [...new Map(findings.map((item) => [`${item.id}\0${item.evidence}`, item])).values()]
  const exact = allowExact.has(text)
  if (exact) unique = unique.filter((item) => item.hardBlock)
  const hardBlock = unique.some((item) => item.hardBlock)
  const status = unique.length === 0 ? 'PASS' : hardBlock || unique.some((item) => item.severity === 'FAIL') ? 'FAIL' : 'REVIEW'
  return {
    policyVersion: POLICY_VERSION,
    status,
    risk: maxRisk(unique),
    mutating,
    destructive,
    hardBlock,
    allowedByExact: exact && unique.length === 0,
    commandPreview: compactCommand(text),
    targets,
    findings: unique,
  }
}

export function formatAnalysis(result) {
  const lines = [
    `[dsh-windows-workspace-guard] ${result.status} (${result.risk})`,
    `policy: ${result.policyVersion}`,
    `mutating: ${result.mutating ? 'yes' : 'no'}`,
    `destructive: ${result.destructive ? 'yes' : 'no'}`,
    `hard-block: ${result.hardBlock ? 'yes' : 'no'}`,
    `command: ${result.commandPreview || '(empty)'}`,
  ]
  for (const item of result.findings) lines.push(`- ${item.id}: ${item.message}${item.evidence ? ` (${item.evidence})` : ''}`)
  return lines.join('\n')
}
