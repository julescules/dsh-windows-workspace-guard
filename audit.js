import { createHash, randomUUID } from 'node:crypto'
import { appendFile, mkdir } from 'node:fs/promises'
import path from 'node:path'

export function commandHash(command) {
  return createHash('sha256').update(String(command), 'utf8').digest('hex')
}

export function createAuditRecord({ command, cwd, result, decision, includeCommand = false, callId = '' }) {
  const record = {
    id: randomUUID(),
    ts: new Date().toISOString(),
    op: 'pwsh-pre-execute',
    callId: String(callId || ''),
    decision,
    status: result.status,
    risk: result.risk,
    policyVersion: result.policyVersion,
    cwd,
    commandSha256: commandHash(command),
    commandPreview: result.commandPreview,
    targets: result.targets,
    findingIds: result.findings.map((item) => item.id),
  }
  if (includeCommand) record.command = result.commandPreview
  return record
}

export async function appendAuditRecord(auditPath, record) {
  if (!auditPath) return { written: false, reason: 'disabled' }
  const resolved = path.resolve(auditPath)
  await mkdir(path.dirname(resolved), { recursive: true })
  await appendFile(resolved, `${JSON.stringify(record)}\n`, { encoding: 'utf8', flag: 'a' })
  return { written: true, path: resolved }
}
