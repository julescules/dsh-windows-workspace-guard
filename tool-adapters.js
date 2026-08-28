import { POLICY_VERSION, analyzePowerShellCommand } from './analyzer.js'

export const DEFAULT_GUARDED_TOOL_NAMES = Object.freeze(['pwsh', 'read', 'write', 'edit', 'str_replace_editor'])
export const SUPPORTED_TOOL_ADAPTERS = Object.freeze({
  pwsh: 'powershell-command',
  powershell: 'powershell-command',
  read: 'official-filesystem-read',
  write: 'official-filesystem-write',
  edit: 'official-filesystem-edit',
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
  if (toolName === 'read') {
    if (typeof args.file_path !== 'string' || !args.file_path.trim()) return undefined
    return `Get-Content -LiteralPath ${quotePowerShellLiteral(args.file_path)}`
  }
  if (toolName === 'write' || toolName === 'edit') {
    if (typeof args.file_path !== 'string' || !args.file_path.trim()) return undefined
    return `Set-Content -LiteralPath ${quotePowerShellLiteral(args.file_path)} -Value '[content omitted]'`
  }
  return undefined
}

export function analyzeToolExecution(exec, options = {}) {
  const toolName = String(exec?.name ?? '').trim().toLowerCase()
  const command = commandForExecution(exec)
  if (command === undefined) return unsupportedResult(toolName)
  return analyzePowerShellCommand(command, options)
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
