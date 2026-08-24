import { execFile as execFileCallback } from 'node:child_process'
import { constants } from 'node:fs'
import { access, lstat, readFile, realpath } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const execFile = promisify(execFileCallback)
export const DOCTOR_SCHEMA_VERSION = 'windows-workspace-guard-doctor/v1'

function fact(id, level, summary, evidence = '') {
  return { id, level, summary, evidence }
}

function errorText(error) {
  return String(error?.code ?? error?.message ?? error).replace(/[\r\n]+/g, ' ').slice(0, 500)
}

function envValue(env, name) {
  if (!env || typeof env !== 'object') return ''
  const direct = env[name]
  if (typeof direct === 'string' && direct.trim()) return direct.trim()
  const key = Object.keys(env).find((candidate) => candidate.toLowerCase() === name.toLowerCase())
  return key && typeof env[key] === 'string' ? env[key].trim() : ''
}

export function resolveDoctorDshHome(options = {}) {
  const env = options.env ?? process.env
  const userProfile = options.userProfile || envValue(env, 'USERPROFILE') || envValue(env, 'HOME')
  const selected = options.dshHome || envValue(env, 'DSH_HOME') || (userProfile ? path.win32.join(userProfile, '.dsh') : '')
  return selected ? path.win32.resolve(options.cwd ?? process.cwd(), selected) : ''
}

function safeProfileName(value) {
  const profile = typeof value === 'string' && value.trim() ? value.trim() : 'web'
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(profile)) throw new TypeError('profile must use only letters, digits, dot, underscore, or hyphen')
  return profile
}

async function pathMetadata(target, operations) {
  try {
    const info = await operations.lstat(target)
    let resolved = target
    try {
      resolved = await operations.realpath(target)
    } catch {
      // The lexical path and lstat result remain useful when realpath fails.
    }
    return { exists: true, isLink: info.isSymbolicLink(), resolved }
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') return { exists: false, isLink: false, resolved: target }
    return { exists: false, isLink: false, resolved: target, error }
  }
}

const ACL_SCRIPT = String.raw`& {
  param([string]$Target)
  $acl = Get-Acl -LiteralPath $Target -ErrorAction Stop
  $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  try { $owner = ([System.Security.Principal.NTAccount]$acl.Owner).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $owner = [string]$acl.Owner }
  $rules = @($acl.Access | ForEach-Object {
    try { $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = [string]$_.IdentityReference }
    [pscustomobject]@{ sid = $sid; rights = [string]$_.FileSystemRights; type = [string]$_.AccessControlType; inherited = [bool]$_.IsInherited }
  })
  [pscustomobject]@{ ownerSid = $owner; currentSid = $current; rules = $rules } | ConvertTo-Json -Depth 5 -Compress
}`

async function runAclCommand(executable, target) {
  const { stdout } = await execFile(executable, [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', ACL_SCRIPT, target,
  ], { encoding: 'utf8', windowsHide: true, timeout: 7000, maxBuffer: 1024 * 1024 })
  return JSON.parse(stdout.trim())
}

/** Read Windows ACL metadata only; credential file contents are never opened. */
export async function queryWindowsAcl(target, options = {}) {
  if (typeof options.aclCommand === 'function') return options.aclCommand(target)
  const preferred = options.pwshPath || envValue(options.env ?? process.env, 'DSH_PWSH_PATH') || 'pwsh.exe'
  try {
    return await runAclCommand(preferred, target)
  } catch (error) {
    if (preferred.toLowerCase() === 'powershell.exe' || (error?.code !== 'ENOENT' && error?.code !== 'UNKNOWN')) throw error
    return runAclCommand('powershell.exe', target)
  }
}

function hasReadableRights(rights) {
  return /(?:FullControl|Modify|ReadAndExecute|ReadData|ReadAttributes|ReadExtendedAttributes|ListDirectory|\bRead\b)/i.test(String(rights))
}

/** Classify only explicit/inherited allow ACEs; deny ACEs and credential values are outside the report. */
export function classifyCredentialAcl(acl) {
  const currentSid = String(acl?.currentSid ?? '')
  const ownerSid = String(acl?.ownerSid ?? '')
  const allowed = new Set([currentSid, ownerSid, 'S-1-5-18', 'S-1-5-32-544'].filter(Boolean).map((value) => value.toUpperCase()))
  const exposed = []
  for (const rule of Array.isArray(acl?.rules) ? acl.rules : []) {
    if (String(rule?.type).toLowerCase() !== 'allow' || !hasReadableRights(rule?.rights)) continue
    const sid = String(rule?.sid ?? '')
    if (!sid || allowed.has(sid.toUpperCase())) continue
    exposed.push({ sid, rights: String(rule.rights), inherited: rule.inherited === true })
  }
  return { ownerSid, currentSid, exposed }
}

function parentCandidates(start) {
  const result = []
  let current = path.win32.dirname(start)
  while (current && !result.includes(current)) {
    result.push(current)
    const next = path.win32.dirname(current)
    if (next === current) break
    current = next
  }
  return result
}

async function inspectAuditPath(auditPath, operations) {
  if (!auditPath) return fact('audit-path', 'INFO', 'JSONL audit is disabled.', '')
  const candidates = parentCandidates(path.win32.resolve(auditPath))
  for (const candidate of candidates) {
    const metadata = await pathMetadata(candidate, operations)
    if (metadata.error) return fact('audit-path', 'WARN', 'The audit path ancestor could not be inspected.', `${candidate}: ${errorText(metadata.error)}`)
    if (!metadata.exists) continue
    try {
      await operations.access(candidate, constants.W_OK)
      return fact('audit-path', 'PASS', 'The deepest existing audit-path ancestor is writable.', candidate)
    } catch (error) {
      return fact('audit-path', 'WARN', 'The deepest existing audit-path ancestor is not writable.', `${candidate}: ${errorText(error)}`)
    }
  }
  return fact('audit-path', 'WARN', 'No existing audit-path ancestor could be inspected.', auditPath)
}

function moduleCandidatePaths(dshHome, profile, argvPath = process.argv[1] ?? '') {
  const packages = ['@deepseek-ai\\dsh-tools', '@deepseek-ai\\dsh-code-runtime', 'dsh-code-runtime-worker-thread']
  const roots = []
  if (dshHome) roots.push(path.win32.join(dshHome, 'profiles', profile, 'node_modules'))
  for (const seed of [argvPath, fileURLToPath(import.meta.url)]) {
    if (!seed) continue
    let current = path.win32.dirname(path.win32.resolve(seed))
    for (let index = 0; index < 10; index += 1) {
      roots.push(path.win32.join(current, 'node_modules'))
      const next = path.win32.dirname(current)
      if (next === current) break
      current = next
    }
  }
  return [...new Set(roots)].flatMap((root) => packages.map((name) => ({ name, path: path.win32.join(root, name) })))
}

async function inspectRuntimeCopies(candidates, operations) {
  const found = new Map()
  for (const candidate of candidates) {
    const metadata = await pathMetadata(candidate.path, operations)
    if (!metadata.exists || metadata.error) continue
    const packageName = candidate.name.replace(/\\/g, '/')
    const list = found.get(packageName) ?? []
    list.push({ lexical: candidate.path, physical: metadata.resolved })
    found.set(packageName, list)
  }

  const duplicateEvidence = []
  const summaryEvidence = []
  for (const [name, entries] of found) {
    const physical = [...new Set(entries.map((entry) => entry.physical.toLowerCase()))]
    summaryEvidence.push(`${name}=${physical.length}`)
    if (physical.length > 1) duplicateEvidence.push(`${name}: ${entries.map((entry) => entry.physical).join(' | ')}`)
  }
  if (duplicateEvidence.length > 0) {
    return fact(
      'runtime-package-copies',
      'WARN',
      'Multiple physical copies of a Harness core runtime package were found; module identity may differ between them.',
      duplicateEvidence.join('; '),
    )
  }
  return fact(
    'runtime-package-copies',
    found.size > 0 ? 'PASS' : 'INFO',
    found.size > 0 ? 'No duplicate physical core-runtime copies were found in the bounded search paths.' : 'No core-runtime package was found in the bounded search paths.',
    summaryEvidence.join(', '),
  )
}

async function inspectConfiguredPath(target, role, operations) {
  const metadata = await pathMetadata(target, operations)
  if (metadata.error) return fact(`${role}-path`, 'WARN', `A configured ${role} path could not be inspected.`, `${target}: ${errorText(metadata.error)}`)
  if (!metadata.exists) return fact(`${role}-path`, 'WARN', `A configured ${role} path does not exist.`, target)
  if (metadata.isLink) return fact(`${role}-path`, 'WARN', `A configured ${role} path is a junction or symbolic link.`, `${target} -> ${metadata.resolved}`)
  return fact(`${role}-path`, 'PASS', `Configured ${role} path exists as a normal filesystem object.`, target)
}

/** Run bounded, read-only Windows/DSH posture checks. */
export async function runWindowsGuardDoctor(options = {}) {
  const operations = {
    lstat: options.lstatImpl ?? lstat,
    realpath: options.realpathImpl ?? realpath,
    access: options.accessImpl ?? access,
    readFile: options.readFileImpl ?? readFile,
  }
  const platform = options.platform ?? process.platform
  const osRelease = options.osRelease ?? os.release()
  const profile = safeProfileName(options.profile)
  const dshHome = resolveDoctorDshHome(options)
  const config = options.config ?? {}
  const facts = []

  facts.push(fact(
    'platform',
    platform === 'win32' ? 'PASS' : 'WARN',
    platform === 'win32' ? 'Running on the intended Windows platform.' : 'This plugin is designed for Windows; platform-specific checks are limited.',
    `${platform} ${osRelease}`,
  ))
  const build = Number(osRelease.split('.')[2] ?? 0)
  if (platform === 'win32' && build === 26200) {
    facts.push(fact(
      'windows-build',
      'WARN',
      'This Windows build appears in a community report about ACL-sandbox pwsh freezes; this is a correlation, not a confirmed diagnosis.',
      'https://github.com/deepseek-ai/deepseek-harness/discussions/3155',
    ))
  } else {
    facts.push(fact('windows-build', 'INFO', 'No build-specific community advisory is matched.', String(build || 'unknown')))
  }
  facts.push(fact(
    'monotonic-tool-guard',
    options.monotonicGuardAvailable === false ? 'WARN' : 'PASS',
    options.monotonicGuardAvailable === false
      ? 'The host has no ctx.tools.guard() API; pre-execute fallback remains active.'
      : 'The host exposes the official monotonic tool guard API.',
    options.monotonicGuardAvailable === false ? 'legacy fallback' : 'ctx.tools.guard',
  ))

  if (!dshHome) {
    facts.push(fact('dsh-home', 'WARN', 'DSH home could not be resolved from arguments or environment.', ''))
  } else {
    const homeMetadata = await pathMetadata(dshHome, operations)
    facts.push(homeMetadata.exists
      ? fact('dsh-home', homeMetadata.isLink ? 'WARN' : 'PASS', homeMetadata.isLink ? 'DSH home is a junction or symbolic link.' : 'DSH home exists.', `${dshHome}${homeMetadata.isLink ? ` -> ${homeMetadata.resolved}` : ''}`)
      : fact('dsh-home', 'WARN', 'DSH home does not exist or cannot be inspected.', homeMetadata.error ? `${dshHome}: ${errorText(homeMetadata.error)}` : dshHome))

    const credentialPath = path.win32.join(dshHome, '.credentials.yaml')
    const credentialMetadata = await pathMetadata(credentialPath, operations)
    if (!credentialMetadata.exists) {
      facts.push(fact('credential-file', credentialMetadata.error ? 'WARN' : 'INFO', credentialMetadata.error ? 'Credential-file metadata could not be inspected.' : 'No managed credential file exists at the default path.', credentialMetadata.error ? errorText(credentialMetadata.error) : credentialPath))
    } else if (platform !== 'win32') {
      facts.push(fact('credential-file', 'INFO', 'Credential file exists; Windows ACL inspection was skipped on this platform.', credentialPath))
    } else {
      try {
        const acl = await queryWindowsAcl(credentialPath, { aclCommand: options.aclInspector, pwshPath: options.pwshPath, env: options.env })
        const classification = classifyCredentialAcl(acl)
        facts.push(classification.exposed.length === 0
          ? fact('credential-acl', 'PASS', 'No readable allow ACE outside the owner, current user, SYSTEM, or Administrators was found.', `owner=${classification.ownerSid || 'unknown'}`)
          : fact('credential-acl', 'WARN', 'Credential ACL grants readable access to an additional identity.', classification.exposed.map((entry) => `${entry.sid}(${entry.rights}${entry.inherited ? ', inherited' : ''})`).join('; ')))
      } catch (error) {
        facts.push(fact('credential-acl', 'WARN', 'Credential ACL metadata could not be collected.', errorText(error)))
      }
    }
  }

  const workspaceRoots = Array.isArray(config.workspaceRoots) ? config.workspaceRoots : []
  const protectedPaths = Array.isArray(config.protectedPaths) ? config.protectedPaths : []
  if (workspaceRoots.length === 0) facts.push(fact('workspace-path', 'INFO', 'No fixed workspaceRoots are configured; each session cwd becomes its effective root.', ''))
  for (const target of workspaceRoots) facts.push(await inspectConfiguredPath(path.win32.resolve(target), 'workspace', operations))
  if (protectedPaths.length === 0) facts.push(fact('protected-path', 'INFO', 'No additional immutable protectedPaths are configured.', ''))
  for (const target of protectedPaths) facts.push(await inspectConfiguredPath(path.win32.resolve(target), 'protected', operations))
  facts.push(await inspectAuditPath(config.auditPath, operations))

  const runtimeCandidates = Array.isArray(options.runtimeCandidates)
    ? options.runtimeCandidates
    : moduleCandidatePaths(dshHome, profile, options.argvPath)
  facts.push(await inspectRuntimeCopies(runtimeCandidates, operations))

  const status = facts.some((item) => item.level === 'FAIL') ? 'FAIL' : facts.some((item) => item.level === 'WARN') ? 'WARN' : 'PASS'
  return {
    schemaVersion: DOCTOR_SCHEMA_VERSION,
    status,
    readOnly: true,
    platform,
    osRelease,
    nodeVersion: process.version,
    dshHome,
    profile,
    facts,
  }
}

export function formatDoctorReport(result) {
  const lines = [
    `[dsh-windows-workspace-guard doctor] ${result.status}`,
    `schema: ${result.schemaVersion}`,
    `platform: ${result.platform} ${result.osRelease}`,
    `node: ${result.nodeVersion}`,
    `dsh-home: ${result.dshHome || '(unresolved)'}`,
    `profile: ${result.profile}`,
    'read-only: yes',
  ]
  for (const item of result.facts) lines.push(`- ${item.level} ${item.id}: ${item.summary}${item.evidence ? ` (${item.evidence})` : ''}`)
  return lines.join('\n')
}
