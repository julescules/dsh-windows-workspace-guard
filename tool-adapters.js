import { POLICY_VERSION, addAnalysisFindings, analyzePowerShellCommand } from './analyzer.js'

export const DEFAULT_GUARDED_TOOL_NAMES = Object.freeze(['pwsh', 'read', 'read_image', 'write', 'edit', 'glob', 'grep', 'str_replace_editor'])
export const SUPPORTED_TOOL_ADAPTERS = Object.freeze({
  pwsh: 'powershell-command',
  powershell: 'powershell-command',
  read: 'official-filesystem-read',
  read_image: 'official-filesystem-image-read',
  write: 'official-filesystem-write',
  edit: 'official-filesystem-edit',
  glob: 'official-filesystem-glob',
  grep: 'official-filesystem-grep',
  'str_replace_editor': 'structured-file-editor',
})

function quotePowerShellLiteral(value) {
  return `'${String(value ?? '').replaceAll("'", "''")}'`
}

function unsupportedResult(toolName) {
  return {
    policyVersion: POLICY_VERSION,
    status: 'FAIL',
    risk: 'CRITICAL',
    mutating: true,
    destructive: false,
    sensitive: false,
    hardBlock: true,
    allowedByExact: false,
    commandPreview: `[unsupported tool schema: ${toolName || '(empty)'}]`,
    targets: [],
    findings: [{
      id: 'unsupported-tool-schema',
      severity: 'CRITICAL',
      message: 'This configured tool has no verified argument adapter; guarding it as PowerShell would create a false safety claim.',
      evidence: toolName || '(empty)',
      hardBlock: true,
    }],
  }
}

/** Convert a verified tool schema into a content-free PowerShell-shaped policy probe. */
export function commandForExecution(exec) {
  const toolName = String(exec?.name ?? '').trim().toLowerCase()
  const args = exec?.arguments && typeof exec.arguments === 'object' ? exec.arguments : {}
  if (toolName === 'pwsh' || toolName === 'powershell') {
    return typeof args.command === 'string' ? args.command : ''
  }
  if (toolName === 'str_replace_editor') {
    const operation = String(args.command ?? '').toLowerCase()
    const target = quotePowerShellLiteral(args.path)
    if (operation === 'view') return `Get-Content -LiteralPath ${target}`
    if (['create', 'str_replace', 'insert'].includes(operation)) return `Set-Content -LiteralPath ${target} -Value '[content omitted]'`
    return undefined
  }
  if (toolName === 'read' || toolName === 'read_image') {
    if (typeof args.file_path !== 'string' || !args.file_path.trim()) return undefined
    return `Get-Content -LiteralPath ${quotePowerShellLiteral(args.file_path)}`
  }
  if (toolName === 'write' || toolName === 'edit') {
    if (typeof args.file_path !== 'string' || !args.file_path.trim()) return undefined
    return `Set-Content -LiteralPath ${quotePowerShellLiteral(args.file_path)} -Value '[content omitted]'`
  }
  if (toolName === 'glob' || toolName === 'grep') {
    if (typeof args.pattern !== 'string' || !args.pattern.trim()) return undefined
    const searchRoot = typeof args.path === 'string' && args.path.trim() ? args.path : '.'
    return toolName === 'glob'
      ? `Get-ChildItem -LiteralPath ${quotePowerShellLiteral(searchRoot)} -Force -Recurse`
      : `Select-String -LiteralPath ${quotePowerShellLiteral(searchRoot)} -Pattern '[pattern omitted]'`
  }
  return undefined
}

function searchFindings(toolName, args, options) {
  if (options.guardSensitiveData === false || !['glob', 'grep'].includes(toolName)) return []
  const values = [args.path, args.include, toolName === 'glob' ? args.pattern : undefined]
    .filter((value) => typeof value === 'string')
  const namesSensitive = values.some((value) => /(?:^|[\\/])(?:\.env(?:\.[^\\/]*)?|\.credentials\.ya?ml|\.git-credentials|\.npmrc|id_(?:rsa|dsa|ecdsa|ed25519))(?:$|[\\/*?])/i.test(value))
  const findings = []
  if (namesSensitive) {
    findings.push({
      id: 'sensitive-search-target',
      severity: 'CRITICAL',
      message: 'The filesystem search explicitly targets a credential-like path or filename.',
      evidence: toolName,
      hardBlock: true,
    })
  }
  if (toolName === 'grep') {
    const include = typeof args.include === 'string' ? args.include.trim() : ''
    if (!include || /^(?:\*|\*\.\*|\*\*[/\\]\*|\*\*[/\\]\*\.\*)$/.test(include)) {
      findings.push({
        id: 'unbounded-sensitive-search',
        severity: 'CRITICAL',
        message: 'Official grep includes hidden and ignored files; set a narrow include glob before searching with sensitive-data protection enabled.',
        evidence: 'grep',
        hardBlock: true,
      })
    }
  }
  return findings
}

export function analyzeToolExecution(exec, options = {}) {
  const toolName = String(exec?.name ?? '').trim().toLowerCase()
  const args = exec?.arguments && typeof exec.arguments === 'object' ? exec.arguments : {}
  const command = commandForExecution(exec)
  if (command === undefined) return unsupportedResult(toolName)
  const result = analyzePowerShellCommand(command, options)
  return addAnalysisFindings(result, searchFindings(toolName, args, options))
}

export function coverageFacts(config) {
  const configured = Array.isArray(config?.toolNames) && config.toolNames.length > 0
    ? config.toolNames
    : DEFAULT_GUARDED_TOOL_NAMES
  return [...new Set(configured.map((value) => String(value).trim().toLowerCase()).filter(Boolean))].map((toolName) => {
    const adapter = SUPPORTED_TOOL_ADAPTERS[toolName]
    return {
      toolName,
      adapter: adapter ?? 'unsupported',
      covered: adapter !== undefined,
    }
  })
}
