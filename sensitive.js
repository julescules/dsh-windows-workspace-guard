import path from 'node:path'

const SENSITIVE_PATH_READ_PATTERN = /(?:\b(?:Get-Content|gc|cat|type|more|Select-String|sls|Import-Clixml|Import-Csv)\b|\[(?:System\.)?IO\.File\]\s*::\s*(?:ReadAllText|ReadAllLines|ReadAllBytes|OpenRead)\s*\()/i
const SENSITIVE_PATH_COPY_PATTERN = /\b(?:Copy-Item|cp|cpi|copy|xcopy|robocopy|Compress-Archive|tar|7z)\b/i
const NETWORK_EGRESS_PATTERN = /\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm|curl|wget|scp|sftp|rsync|rclone|azcopy)\b/i
const ENV_ENUMERATION_PATTERN = /\b(?:Get-ChildItem|gci|dir|ls)\b[^\r\n;|&]*\bEnv:\s*(?:$|[;|&])/i
const ENV_REFERENCE_PATTERN = /\$env:([A-Za-z_][A-Za-z0-9_]*)|\$\{env:([^}]+)\}/gi
const ENV_GET_PATTERN = /\[(?:System\.)?Environment\]\s*::\s*GetEnvironmentVariable\s*\(\s*['"]([^'"]+)['"]/gi

const HARD_FINDING = Object.freeze({ severity: 'CRITICAL', hardBlock: true })

function finding(id, message, evidence) {
  return { id, ...HARD_FINDING, message, evidence }
}

function envValue(env, name) {
  if (!env || typeof env !== 'object') return ''
  const direct = env[name]
  if (typeof direct === 'string' && direct.trim()) return direct.trim()
  const key = Object.keys(env).find((candidate) => candidate.toLowerCase() === name.toLowerCase())
  return key && typeof env[key] === 'string' ? env[key].trim() : ''
}

function normalizePath(value, { cwd, userProfile }) {
  if (typeof value !== 'string' || !value.trim()) return ''
  let candidate = value.trim()
  if (/^~(?:[\\/]|$)/.test(candidate) && userProfile) candidate = `${userProfile}${candidate.slice(1)}`
  return path.win32.resolve(cwd, candidate).replace(/[\\/]+$/, '')
}

function uniquePaths(values, options) {
  const seen = new Set()
  const result = []
  for (const value of values) {
    const normalized = normalizePath(value, options)
    if (!normalized) continue
    const key = normalized.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    result.push(normalized)
  }
  return result
}

/** Resolve conservative default locations that commonly contain reusable credentials on Windows. */
export function defaultSensitivePaths(options = {}) {
  const env = options.env ?? process.env
  const cwd = options.cwd ?? process.cwd()
  const userProfile = options.userProfile
    ?? envValue(env, 'USERPROFILE')
    ?? envValue(env, 'HOME')
  const dshHome = options.dshHome
    ?? envValue(env, 'DSH_HOME')
    ?? (userProfile ? path.win32.join(userProfile, '.dsh') : '')
  const appData = options.appData ?? envValue(env, 'APPDATA')
  const candidates = [
    dshHome && path.win32.join(dshHome, '.credentials.yaml'),
    dshHome && path.win32.join(dshHome, '.env'),
    userProfile && path.win32.join(userProfile, '.ssh'),
    userProfile && path.win32.join(userProfile, '.aws'),
    userProfile && path.win32.join(userProfile, '.azure'),
    userProfile && path.win32.join(userProfile, '.git-credentials'),
    userProfile && path.win32.join(userProfile, '.npmrc'),
    userProfile && path.win32.join(userProfile, '.config', 'gh', 'hosts.yml'),
    appData && path.win32.join(appData, 'GitHub CLI', 'hosts.yml'),
    appData && path.win32.join(appData, 'NuGet', 'NuGet.Config'),
  ].filter(Boolean)
  return uniquePaths(candidates, { cwd, userProfile })
}

/** Merge operator-supplied sensitive roots with the Windows defaults. */
export function resolveSensitivePaths(options = {}) {
  const env = options.env ?? process.env
  const cwd = options.cwd ?? process.cwd()
  const userProfile = options.userProfile
    ?? envValue(env, 'USERPROFILE')
    ?? envValue(env, 'HOME')
  const defaults = options.includeDefaults === false ? [] : defaultSensitivePaths({ ...options, env, cwd, userProfile })
  const configured = Array.isArray(options.sensitivePaths) ? options.sensitivePaths : []
  return uniquePaths([...defaults, ...configured], { cwd, userProfile })
}

function isPathBoundary(character) {
  return character === undefined || /[\s'"`;|&(),=<>]/.test(character)
}

function mentionsNormalizedPath(command, candidate) {
  const haystack = command.replace(/\//g, '\\').toLowerCase()
  const needle = candidate.replace(/\//g, '\\').toLowerCase()
  let offset = 0
  while (offset <= haystack.length - needle.length) {
    const index = haystack.indexOf(needle, offset)
    if (index < 0) return false
    const before = index === 0 ? undefined : haystack[index - 1]
    const after = haystack[index + needle.length]
    if (isPathBoundary(before) && (after === '\\' || isPathBoundary(after))) return true
    offset = index + 1
  }
  return false
}

function dynamicSensitiveMentions(command) {
  const patterns = [
    [/(?:\$env:DSH_HOME|\$\{env:DSH_HOME\})[\\/]+\.credentials\.yaml\b/i, '$DSH_HOME\\.credentials.yaml'],
    [/(?:\$env:DSH_HOME|\$\{env:DSH_HOME\})[\\/]+\.env\b/i, '$DSH_HOME\\.env'],
    [/(?:\$HOME|\$env:USERPROFILE|\$\{env:USERPROFILE\})[\\/]+\.ssh(?:[\\/]|\b)/i, '$USERPROFILE\\.ssh'],
    [/(?:\$HOME|\$env:USERPROFILE|\$\{env:USERPROFILE\})[\\/]+\.aws(?:[\\/]|\b)/i, '$USERPROFILE\\.aws'],
    [/(?:\$HOME|\$env:USERPROFILE|\$\{env:USERPROFILE\})[\\/]+\.azure(?:[\\/]|\b)/i, '$USERPROFILE\\.azure'],
    [/(?:\$HOME|\$env:USERPROFILE|\$\{env:USERPROFILE\})[\\/]+(?:\.git-credentials|\.npmrc)\b/i, '$USERPROFILE credential file'],
    [/(?:\$HOME|\$env:USERPROFILE|\$\{env:USERPROFILE\})[\\/]+\.config[\\/]gh[\\/]hosts\.yml\b/i, '$USERPROFILE\\.config\\gh\\hosts.yml'],
  ]
  return patterns.filter(([pattern]) => pattern.test(command)).map(([, label]) => label)
}

function sensitiveBasenameMentions(command) {
  const pattern = /(?:^|[\\/'"\s])((?:\.env(?:\.[A-Za-z0-9_-]+)?|\.credentials\.ya?ml|\.git-credentials|\.npmrc|id_(?:rsa|dsa|ecdsa|ed25519)))(?=$|[\s'"`;|&),])/gi
  const names = []
  let match
  while ((match = pattern.exec(command)) !== null) names.push(match[1])
  return [...new Set(names.map((value) => value.toLowerCase()))]
}

function mentionedSensitivePaths(command, options) {
  const resolved = resolveSensitivePaths(options)
  const literal = resolved.filter((candidate) => mentionsNormalizedPath(command, candidate))
  return [...new Set([...literal, ...dynamicSensitiveMentions(command), ...sensitiveBasenameMentions(command)])]
}

/** Avoid suffix-only false positives such as MONKEY while covering common secret variable conventions. */
export function isSensitiveEnvironmentName(value) {
  if (typeof value !== 'string') return false
  const name = value.trim().toUpperCase()
  if (!name) return false
  if (/^(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET)$/.test(name)) return true
  return /(?:^|_)(?:API_KEY|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|SECRET_ACCESS_KEY|CLIENT_SECRET|CREDENTIALS?)$/.test(name)
}

function sensitiveEnvironmentReads(command) {
  const names = []
  ENV_REFERENCE_PATTERN.lastIndex = 0
  let match
  while ((match = ENV_REFERENCE_PATTERN.exec(command)) !== null) {
    const name = match[1] ?? match[2] ?? ''
    if (!isSensitiveEnvironmentName(name)) continue
    const tail = command.slice(ENV_REFERENCE_PATTERN.lastIndex)
    if (/^\s*=/.test(tail)) continue
    names.push(name.toUpperCase())
  }
  ENV_GET_PATTERN.lastIndex = 0
  while ((match = ENV_GET_PATTERN.exec(command)) !== null) {
    if (isSensitiveEnvironmentName(match[1])) names.push(match[1].toUpperCase())
  }
  return [...new Set(names)]
}

/**
 * Identify explicit credential reads, copies, and outbound use at the pwsh command boundary.
 * This is deliberately literal and conservative; it is not a general data-loss-prevention engine.
 */
export function analyzeSensitiveCommand(command, options = {}) {
  if (options.enabled === false || typeof command !== 'string' || !command.trim()) {
    return { sensitive: false, findings: [] }
  }

  const findings = []
  const paths = mentionedSensitivePaths(command, options)
  const environmentNames = sensitiveEnvironmentReads(command)
  const enumeratesEnvironment = ENV_ENUMERATION_PATTERN.test(command)
  const usesNetwork = NETWORK_EGRESS_PATTERN.test(command)

  if (paths.length > 0 && SENSITIVE_PATH_READ_PATTERN.test(command)) {
    findings.push(finding(
      'sensitive-path-read',
      'The command explicitly reads a configured credential or secret-bearing path.',
      paths.join(', '),
    ))
  }
  if (paths.length > 0 && SENSITIVE_PATH_COPY_PATTERN.test(command)) {
    findings.push(finding(
      'sensitive-path-copy',
      'The command explicitly copies or archives a configured credential or secret-bearing path.',
      paths.join(', '),
    ))
  }
  if (environmentNames.length > 0) {
    findings.push(finding(
      'sensitive-environment-read',
      'The command explicitly reads an environment variable whose name denotes a credential.',
      environmentNames.join(', '),
    ))
  }
  if (enumeratesEnvironment) {
    findings.push(finding(
      'sensitive-environment-enumeration',
      'Enumerating the complete environment can expose provider keys and access tokens to the model output.',
      'Env:',
    ))
  }
  if (usesNetwork && (paths.length > 0 || environmentNames.length > 0 || enumeratesEnvironment)) {
    findings.push(finding(
      'sensitive-network-egress',
      'The same command combines an outbound network utility with an explicit sensitive source.',
      [...paths, ...environmentNames, ...(enumeratesEnvironment ? ['Env:'] : [])].join(', '),
    ))
  }

  return { sensitive: findings.length > 0, findings }
}
