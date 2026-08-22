import { defineTool } from '@deepseek-ai/dsh-tools'
import { installSettingsSection, settingsNamespace } from '@deepseek-ai/dsh-settings'
import Schema from '@deepseek-ai/schemastery'
import { analyzePowerShellCommand, formatAnalysis } from './analyzer.js'
import { appendAuditRecord, createAuditRecord } from './audit.js'
import { createConfigSource, guardedToolNames } from './config-source.js'
import { decide, normalizeMode } from './policy.js'

export const name = 'dsh-windows-workspace-guard'
export const inject = ['tools', 'settings']
export const SETTINGS_NAMESPACE = settingsNamespace('windows-workspace-guard')

export const Config = Schema.object({
  enabled: Schema.boolean().default(true),
  mode: Schema.string().default('block'),
  reportOnly: Schema.boolean().default(false),
  toolNames: Schema.array(Schema.string()).default(['pwsh']),
  workspaceRoots: Schema.array(Schema.string()).default([]),
  protectedPaths: Schema.array(Schema.string()).default([]),
  allowExact: Schema.array(Schema.string()).default([]),
  guardGit: Schema.boolean().default(true),
  guardSystem: Schema.boolean().default(true),
  guardProcesses: Schema.boolean().default(true),
  guardNativeEscapes: Schema.boolean().default(true),
  guardPersistentShell: Schema.boolean().default(true),
  requireAbsoluteMutationPaths: Schema.boolean().default(true),
  logDecisions: Schema.boolean().default(true),
  auditPath: Schema.string().default(''),
  auditIncludeCommand: Schema.boolean().default(false),
  auditFailClosed: Schema.boolean().default(false),
})

function sessionCwd(exec) {
  return exec?.agent?.session?.header?.cwd
    ?? exec?.agent?.header?.cwd
    ?? exec?.agent?.cwd
    ?? exec?.arguments?.workdir
    ?? process.cwd()
}

function outputSchema() {
  return {
    type: 'object',
    additionalProperties: false,
    properties: {
      policyVersion: { type: 'string', required: true },
      status: { type: 'string', required: true },
      risk: { type: 'string', required: true },
      mutating: { type: 'boolean', required: true },
      destructive: { type: 'boolean', required: true },
      hardBlock: { type: 'boolean', required: true },
      allowedByExact: { type: 'boolean', required: true },
      commandPreview: { type: 'string', required: true },
      targets: { type: 'array', required: true, items: { type: 'string' } },
      findings: {
        type: 'array',
        required: true,
        items: {
          type: 'object',
          additionalProperties: false,
          properties: {
            id: { type: 'string', required: true },
            severity: { type: 'string', required: true },
            message: { type: 'string', required: true },
            evidence: { type: 'string', required: true },
            hardBlock: { type: 'boolean', required: true },
          },
        },
      },
    },
  }
}

function analyze(command, cwd, config) {
  const roots = config.workspaceRoots.length > 0 ? config.workspaceRoots : [cwd]
  return analyzePowerShellCommand(command, {
    cwd,
    workspaceRoots: roots,
    protectedPaths: config.protectedPaths,
    allowExact: config.allowExact,
    guardGit: config.guardGit,
    guardSystem: config.guardSystem,
    guardProcesses: config.guardProcesses,
    guardNativeEscapes: config.guardNativeEscapes,
    guardPersistentShell: config.guardPersistentShell,
    requireAbsoluteMutationPaths: config.requireAbsoluteMutationPaths,
  })
}

function decisionReason(result) {
  const ids = result.findings.map((item) => item.id).join(', ')
  return `[windows-workspace-guard] ${result.hardBlock ? 'hard block' : 'policy review'}: ${ids}`
}

export function apply(ctx, config) {
  const source = createConfigSource(config)
  installSettingsSection(ctx, SETTINGS_NAMESPACE, Config, config, {
    setSource: (current) => { source.setSource(current) },
    onChange: () => {},
  })

  ctx.on('tools/pre-execute', async (exec, next) => {
    const active = source.get()
    if (!active.enabled || !guardedToolNames(active).has(String(exec.name).toLowerCase())) return next()
    const command = typeof exec.arguments?.command === 'string' ? exec.arguments.command : ''
    const cwd = sessionCwd(exec)
    const result = analyze(command, cwd, active)
    const action = decide(result, normalizeMode(active.mode, active.reportOnly))

    if (active.logDecisions && result.mutating) {
      console.log(`[dsh-windows-workspace-guard] ${action.auditDecision} ${result.status} ${result.commandPreview}`)
    }

    if (active.auditPath && result.mutating) {
      try {
        const record = createAuditRecord({
          command,
          cwd,
          result,
          decision: action.auditDecision,
          includeCommand: active.auditIncludeCommand,
          callId: exec.callId,
        })
        await appendAuditRecord(active.auditPath, record)
      } catch (error) {
        console.error(`[dsh-windows-workspace-guard] audit write failed: ${error instanceof Error ? error.message : String(error)}`)
        if (active.auditFailClosed) return { kind: 'deny', reason: '[windows-workspace-guard] audit write failed (fail-closed)' }
      }
    }

    if (action.kind === 'deny') return { kind: 'deny', reason: decisionReason(result) }
    if (action.kind === 'ask') return { kind: 'ask', reason: decisionReason(result) }
    return next()
  })

  ctx.tools.register(defineTool({
    name: 'windows_workspace_guard_check',
    description: 'Checks a PowerShell or Git command against Windows workspace, immutable-path, and destructive-operation policy without executing it.',
    parameters: {
      command: { type: 'string', required: true, description: 'PowerShell command to inspect.' },
      cwd: { type: 'string', description: 'Working directory used to resolve relative paths.' },
    },
    output: {
      schema: outputSchema(),
      render: (_args, value) => [{ type: 'text', text: formatAnalysis(value) }],
    },
    async execute(args, exec) {
      const active = source.get()
      const cwd = args.cwd || sessionCwd(exec)
      return analyze(args.command, cwd, active)
    },
  }))
}
