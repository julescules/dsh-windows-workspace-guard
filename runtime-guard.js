import { analyzePowerShellCommand } from './analyzer.js'
import { guardedToolNames } from './config-source.js'

export function executionCwd(exec, fallback = process.cwd()) {
  return exec?.agent?.session?.header?.cwd
    ?? exec?.agent?.header?.cwd
    ?? exec?.agent?.cwd
    ?? exec?.arguments?.workdir
    ?? fallback
}

export function executionCommand(exec) {
  return typeof exec?.arguments?.command === 'string' ? exec.arguments.command : ''
}

export function staticAnalysisForExecution(exec, config, fallbackCwd = process.cwd()) {
  const cwd = executionCwd(exec, fallbackCwd)
  const roots = Array.isArray(config?.workspaceRoots) && config.workspaceRoots.length > 0
    ? config.workspaceRoots
    : [cwd]
  return analyzePowerShellCommand(executionCommand(exec), {
    cwd,
    workspaceRoots: roots,
    protectedPaths: config?.protectedPaths,
    allowExact: config?.allowExact,
    guardGit: config?.guardGit,
    guardSystem: config?.guardSystem,
    guardProcesses: config?.guardProcesses,
    guardNativeEscapes: config?.guardNativeEscapes,
    guardPersistentShell: config?.guardPersistentShell,
    guardSensitiveData: config?.guardSensitiveData,
    sensitivePaths: config?.sensitivePaths,
    requireAbsoluteMutationPaths: config?.requireAbsoluteMutationPaths,
  })
}

export function decisionReason(result) {
  const ids = result.findings.map((item) => item.id).join(', ')
  return `[windows-workspace-guard] ${result.hardBlock ? 'hard block' : 'policy review'}: ${ids}`
}

/** Synchronous, side-effect-free reason function for the official monotonic ToolRuntime guard. */
export function monotonicGuardReason(exec, config, fallbackCwd = process.cwd()) {
  if (!config?.enabled || !guardedToolNames(config).has(String(exec?.name ?? '').toLowerCase())) return undefined
  const result = staticAnalysisForExecution(exec, config, fallbackCwd)
  return result.hardBlock ? decisionReason(result) : undefined
}

/** Install the rc.2 guard when available; older Harness builds retain pre-execute enforcement. */
export function installMonotonicGuard(ctx, source) {
  if (typeof ctx?.tools?.guard !== 'function') return { installed: false, dispose: undefined }
  const dispose = ctx.tools.guard((exec) => monotonicGuardReason(exec, source.get()))
  return { installed: true, dispose }
}
