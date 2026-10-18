import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import { createInterface } from 'node:readline'
import { pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'

const DECISIONS = ['allowed', 'blocked', 'blocked-hard', 'reported', 'approval-requested', 'approved-dispatch', 'approval-rejected']

function timestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new RangeError('Timestamp must be ISO 8601 with an explicit timezone')
  }
  const date = value.slice(0, 10)
  if (new Date(`${date}T00:00:00Z`).toISOString().slice(0, 10) !== date || Number(value.slice(11, 13)) > 23) throw new RangeError('Invalid calendar timestamp')
  return Date.parse(value)
}

// Only aggregate allowlisted fields: never return commands, cwd, or targets.
export async function summarizeAudit(file, { maxRecords = 100000, maxBytes = 32 * 1024 * 1024, since, until, decision } = {}) {
  if (!Number.isSafeInteger(maxRecords) || maxRecords < 1 || !Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new RangeError('Invalid audit limit')
  const start = since === undefined ? -Infinity : timestamp(since)
  const end = until === undefined ? Infinity : timestamp(until)
  if (start > end || (decision !== undefined && !DECISIONS.includes(decision))) throw new RangeError('Invalid audit filter')
  const info = await stat(file)
  if (!info.isFile() || info.size > maxBytes) {
    const error = new Error('Audit must be a regular file within the byte limit')
    error.code = 'AUDIT_SIZE_LIMIT'
    throw error
  }
  const report = { schema: 'windows-guard-audit-summary/v1', records: 0, malformed: 0, truncated: false, decisions: {}, findings: {} }
  report.matched = 0
  report.excluded = 0
  report.invalidTimestamps = 0
  const counts = new Map(), decisions = new Map()
  const stream = createReadStream(file, { encoding: 'utf8', end: maxBytes - 1 })
  const lines = createInterface({ input: stream, crlfDelay: Infinity })
  try {
    for await (const line of lines) {
      if (!line.trim()) continue
      if (report.records + report.malformed >= maxRecords) { report.truncated = true; break }
      let row
      try { row = JSON.parse(line) } catch { report.malformed++; continue }
      if (!row || typeof row !== 'object' || !Array.isArray(row.findingIds) || typeof row.decision !== 'string') { report.malformed++; continue }
      report.records++
      if (since !== undefined || until !== undefined) {
        let time
        try { time = timestamp(row.ts) } catch { report.invalidTimestamps++; report.excluded++; continue }
        if (time < start || time > end) { report.excluded++; continue }
      }
      if (decision !== undefined && row.decision !== decision) { report.excluded++; continue }
      report.matched++
      const label = DECISIONS.includes(row.decision) ? row.decision : 'other'
      decisions.set(label, (decisions.get(label) || 0) + 1)
      for (const id of new Set(row.findingIds)) {
        if (typeof id === 'string' && /^[a-z][a-z0-9-]{0,79}$/.test(id)) counts.set(id, (counts.get(id) || 0) + 1)
      }
    }
  } finally { lines.close(); stream.destroy() }
  report.decisions = Object.fromEntries(decisions)
  if ((await stat(file)).size > info.size) report.truncated = true
  report.findings = Object.fromEntries([...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])))
  return report
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const { values, positionals } = parseArgs({ allowPositionals: true, options: { since: { type: 'string' }, until: { type: 'string' }, decision: { type: 'string' } } })
    if (positionals.length !== 1) throw new Error('Usage: node audit-summary.js <audit.jsonl> [--since ISO] [--until ISO] [--decision blocked-hard]')
    console.log(JSON.stringify(await summarizeAudit(positionals[0], values), null, 2))
  }
  catch (error) { console.error(`Audit summary failed: ${error.code || error.name}`); process.exitCode = 2 }
}
