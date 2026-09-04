import { defineTool } from '@deepseek-ai/dsh-tools'
import Schema from '@deepseek-ai/schemastery'
import { formatAnalysis } from './analyzer.js'
import { appendAuditRecord, createAuditRecord } from './audit.js'
import { createConfigSource, guardedToolNames } from './config-source.js'
import { formatDoctorReport, runWindowsGuardDoctor } from './doctor.js'
import { decide, normalizeMode } from './policy.js'
import { guardAnalysisTargets } from './path-guard.js'
import { decisionReason, executionCommand, executionCwd, installMonotonicGuard } from './runtime-guard.js'
import { analyzeToolExecution } from './tool-adapters.js'

export const name = 'dsh-windows-workspace-guard'
export const inject = ['tools', 'settings']
export const SETTINGS_NAMESPACE = 'windows-workspace-guard'

export const Config = Schema.object({
  enabled: Schema.boolean().default(true),
  mode: Schema.string().default('block'),
  reportOnly: Schema.boolean().default(false),
  toolNames: Schema.array(Schema.string()).default(['pwsh', 'read', 'read_image', 'write', 'edit', 'glob', 'grep', 'str_replace_editor']),
  workspaceRoots: Schema.array(Schema.string()).default([]),
  protectedPaths: Schema.array(Schema.string()).default([]),
  allowExact: Schema.array(Schema.string()).default([]),
  guardGit: Schema.boolean().default(true),
  guardSystem: Schema.boolean().default(true),
  guardProcesses: Schema.boolean().default(true),
  guardNativeEscapes: Schema.boolean().default(true),
  guardExistingLinks: Schema.boolean().default(true),
  guardSensitiveData: Schema.boolean().default(true),
  sensitivePaths: Schema.array(Schema.string()).default([]),
  guardPersistentShell: Schema.boolean().default(true),
  requireAbsoluteMutationPaths: Schema.boolean().default(true),
  logDecisions: Schema.boolean().default(true),
  auditPath: Schema.string().default(''),
  auditIncludeCommand: Schema.boolean().default(false),
  auditFailClosed: Schema.boolean().default(false),
})

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
      sensitive: { type: 'boolean', required: true },
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

function doctorOutputSchema() {
  return {
    type: 'object',
    additionalProperties: false,
    properties: {
      schemaVersion: { type: 'string', required: true },
      status: { type: 'string', required: true },
      readOnly: { type: 'boolean', required: true },
      platform: { type: 'string', required: true },
      osRelease: { type: 'string', required: true },
      nodeVersion: { type: 'string', required: true },
      dshHome: { type: 'string', required: true },
      profile: { type: 'string', required: true },
      facts: {
        type: 'array',
        required: true,
        items: {
          type: 'object',
          additionalProperties: false,
          properties: {
            id: { type: 'string', required: true },
            level: { type: 'string', required: true },
            summary: { type: 'string', required: true },
            evidence: { type: 'string', required: true },
          },
        },
      },
    },
  }
}

async function analyzeExecution(exec, config) {
  const cwd = executionCwd(exec)
  const roots = Array.isArray(config.workspaceRoots) && config.workspaceRoots.length > 0 ? config.workspaceRoots : [cwd]
  const result = analyzeToolExecution(exec, {
    cwd,
    workspaceRoots: roots,
    protectedPaths: Array.isArray(config.protectedPaths) ? config.protectedPaths : [],
    allowExact: Array.isArray(config.allowExact) ? config.allowExact : [],
    guardGit: config.guardGit,
    guardSystem: config.guardSystem,
    guardProcesses: config.guardProcesses,
    guardNativeEscapes: config.guardNativeEscapes,
    guardSensitiveData: config.guardSensitiveData,
    sensitivePaths: Array.isArray(config.sensitivePaths) ? config.sensitivePaths : [],
    guardPersistentShell: config.guardPersistentShell,
    requireAbsoluteMutationPaths: config.requireAbsoluteMutationPaths,
  })
  return guardAnalysisTargets(result, { cwd, enabled: config.guardExistingLinks })
}

function executionKey(exec) {
  return exec?.token ?? exec
}

function auditFailureResult() {
  const message = '[windows-workspace-guard] audit write failed (fail-closed)'
  return {
    content: [{ type: 'text', text: `Error: ${message}` }],
    isError: true,
    error: { message, info: { name: 'WorkspaceGuardAuditError', code: 'WORKSPACE_GUARD_AUDIT_FAILED' } },
  }
}

async function writePendingAudit(pending, decision) {
  const record = createAuditRecord({
    command: pending.command,
    cwd: pending.cwd,
    result: pending.result,
    decision,
    includeCommand: pending.config.auditIncludeCommand,
    callId: pending.callId,
  })
  await appendAuditRecord(pending.config.auditPath, record)
}

export function apply(ctx, config) {
  const source = createConfigSource(config)
  ctx.settings.installSection(ctx, SETTINGS_NAMESPACE, Config, config, {
    setSource: (current) => { source.setSource(current) },
    onChange: () => {},
  })
  const monotonic = installMonotonicGuard(ctx, source)
  const pendingAudits = new Map()

  ctx.on('tools/pre-execute', async (exec, next) => {
    const active = source.get()
    if (!active.enabled || !guardedToolNames(active).has(String(exec.name).toLowerCase())) return next()
    const cwd = executionCwd(exec)
    const command = executionCommand(exec)
    const result = await analyzeExecution(exec, active)
    const action = decide(result, normalizeMode(active.mode, active.reportOnly))

    const relevant = result.mutating || result.sensitive
    if (active.logDecisions && relevant) {
      console.log(`[dsh-windows-workspace-guard] ${action.auditDecision} ${result.status} ${result.commandPreview}`)
    }

    if (active.auditPath && relevant) {
      pendingAudits.set(executionKey(exec), { command, cwd, result, action, config: { ...active }, callId: exec.callId })
    }

    if (action.kind === 'deny') return { kind: 'deny', reason: decisionReason(result) }
    if (action.kind === 'ask') return { kind: 'ask', reason: decisionReason(result) }
    return next()
  })

  // This wrapper runs after ask approval and monotonic guards.  It avoids any
  // audit-file mutation before the host has authorized dispatch.
  ctx.on('tools/execute', async (exec, next) => {
    const key = executionKey(exec)
    const pending = pendingAudits.get(key)
    if (!pending) return next()
    pendingAudits.delete(key)
    try {
      const decision = pending.action.kind === 'ask' ? 'approved-dispatch' : pending.action.auditDecision
      await writePendingAudit(pending, decision)
    } catch (error) {
      console.error(`[dsh-windows-workspace-guard] audit write failed: ${error instanceof Error ? error.message : String(error)}`)
      if (pending.config.auditFailClosed) return auditFailureResult()
    }
    return next()
  })

  // Denied calls never dispatch.  Record them only after the immutable final
  // result exists; this observer intentionally does not affect authorization.
  ctx.on('tools/result', (exec) => {
    const key = executionKey(exec)
    const pending = pendingAudits.get(key)
    if (!pending) return
    pendingAudits.delete(key)
    const decision = pending.action.kind === 'ask' ? 'approval-rejected' : pending.action.auditDecision
    void writePendingAudit(pending, decision).catch((error) => {
      console.error(`[dsh-windows-workspace-guard] audit write failed after denial: ${error instanceof Error ? error.message : String(error)}`)
    })
  })

  ctx.tools.register(defineTool({
    name: 'windows_workspace_guard_check',
    description: 'Dry-runs an official PowerShell or filesystem tool call against Windows workspace and sensitive-data policy without executing it.',
    parameters: {
      toolName: { type: 'string', enum: ['pwsh', 'read', 'read_image', 'write', 'edit', 'glob', 'grep', 'str_replace_editor'], description: 'Verified official tool schema to inspect. Defaults to pwsh.' },
      command: { type: 'string', description: 'PowerShell command, or str_replace_editor operation: view/create/str_replace/insert.' },
      path: { type: 'string', description: 'File path for read/write/edit or an absolute path for str_replace_editor.' },
      pattern: { type: 'string', description: 'Required pattern for glob or grep.' },
      include: { type: 'string', description: 'Narrow file glob for grep; required by the default sensitive-data policy.' },
      cwd: { type: 'string', description: 'Working directory used to resolve relative paths.' },
    },
    output: {
      schema: outputSchema(),
      render: (_args, value) => [{ type: 'text', text: formatAnalysis(value) }],
    },
    async execute(args, exec) {
      const active = source.get()
      const cwd = args.cwd || executionCwd(exec)
      const toolName = args.toolName || 'pwsh'
      const toolArguments = toolName === 'str_replace_editor'
        ? { command: args.command, path: args.path, workdir: cwd }
        : ['read', 'read_image', 'write', 'edit'].includes(toolName)
          ? { file_path: args.path, workdir: cwd }
          : ['glob', 'grep'].includes(toolName)
            ? { pattern: args.pattern, path: args.path, include: args.include, workdir: cwd }
          : { command: args.command, workdir: cwd }
      return await analyzeExecution({ name: toolName, arguments: toolArguments, agent: { cwd } }, active)
    },
  }))

  ctx.tools.register(defineTool({
    name: 'windows_workspace_guard_doctor',
    description: 'Runs bounded, read-only Windows Workspace Guard diagnostics: effective roots, link state, audit path, DSH runtime copies, and credential ACL metadata. It never reads credential values or changes ACLs.',
    parameters: {
      profile: { type: 'string', description: 'DSH profile name to inspect. Defaults to web.' },
      dshHome: { type: 'string', description: 'Optional DSH home override. Defaults to DSH_HOME or the user .dsh directory.' },
    },
    output: {
      schema: doctorOutputSchema(),
      render: (_args, value) => [{ type: 'text', text: formatDoctorReport(value) }],
    },
    async execute(args) {
      return runWindowsGuardDoctor({
        profile: args.profile,
        dshHome: args.dshHome,
        config: source.get(),
        monotonicGuardAvailable: monotonic.installed,
      })
    },
  }))
}
