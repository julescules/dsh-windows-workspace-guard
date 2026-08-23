import { lstat, realpath } from 'node:fs/promises'
import path from 'node:path'
import { addAnalysisFindings } from './analyzer.js'

const ABSOLUTE_WINDOWS_PATH = /^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+(?:\\|$))/

function finding(id, message, evidence) {
  return { id, severity: 'CRITICAL', message, evidence, hardBlock: true }
}

export function windowsPathPrefixes(target, cwd = process.cwd()) {
  if (typeof target !== 'string' || !ABSOLUTE_WINDOWS_PATH.test(target)) return []
  const resolved = path.win32.resolve(cwd, target)
  const root = path.win32.parse(resolved).root
  const relative = resolved.slice(root.length)
  const parts = relative.split(/[\\/]+/).filter(Boolean)
  const prefixes = [root]
  let current = root
  for (const part of parts) {
    current = path.win32.join(current, part)
    prefixes.push(current)
  }
  return prefixes
}

export async function inspectExistingPathLinks(target, options = {}) {
  const prefixes = windowsPathPrefixes(target, options.cwd)
  if (prefixes.length === 0) return []
  const stat = options.lstatImpl ?? lstat
  const resolveReal = options.realpathImpl ?? realpath
  const findings = []

  for (const prefix of prefixes) {
    let info
    try {
      info = await stat(prefix)
    } catch (error) {
      if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') break
      findings.push(finding(
        'path-inspection-failed',
        'An existing target prefix could not be inspected, so link traversal cannot be proven safe.',
        `${prefix}: ${error?.code ?? error?.message ?? String(error)}`,
      ))
      break
    }
    if (!info.isSymbolicLink()) continue

    let destination = '(unresolved)'
    try {
      destination = await resolveReal(prefix)
    } catch {
      // The link itself is sufficient evidence. Keep the unresolved marker.
    }
    findings.push(finding(
      'existing-reparse-point',
      'The mutation target traverses an existing junction or symbolic link; the effective filesystem destination is not the inspected lexical path.',
      `${prefix} -> ${destination}`,
    ))
    break
  }
  return findings
}

export async function guardAnalysisTargets(result, options = {}) {
  if (options.enabled === false || !result?.mutating || !Array.isArray(result.targets)) return result
  const additions = []
  const targets = [...new Set(result.targets.filter((target) => typeof target === 'string'))]
  for (const target of targets) additions.push(...await inspectExistingPathLinks(target, options))
  return addAnalysisFindings(result, additions)
}
