import { createReadStream } from 'node:fs'
import { createInterface } from 'node:readline'
import { pathToFileURL } from 'node:url'

// Only aggregate allowlisted fields: never return commands, cwd, or targets.
export async function summarizeAudit(file, { maxRecords = 100000 } = {}) {
  const report = { schema: 'windows-guard-audit-summary/v1', records: 0, malformed: 0, truncated: false, decisions: {}, findings: {} }
  const counts = new Map(), decisions = new Map()
  const stream = createReadStream(file, { encoding: 'utf8' })
  const lines = createInterface({ input: stream, crlfDelay: Infinity })
  try {
    for await (const line of lines) {
      if (!line.trim()) continue
      if (report.records + report.malformed >= maxRecords) { report.truncated = true; break }
      let row
      try { row = JSON.parse(line) } catch { report.malformed++; continue }
      if (!row || typeof row !== 'object' || !Array.isArray(row.findingIds) || typeof row.decision !== 'string') { report.malformed++; continue }
      report.records++
      const decision = ['allowed', 'blocked', 'blocked-hard', 'reported', 'approval-requested', 'approved-dispatch', 'approval-rejected'].includes(row.decision) ? row.decision : 'other'
      decisions.set(decision, (decisions.get(decision) || 0) + 1)
      for (const id of new Set(row.findingIds)) {
        if (typeof id === 'string' && /^[a-z][a-z0-9-]{0,79}$/.test(id)) counts.set(id, (counts.get(id) || 0) + 1)
      }
    }
  } finally { lines.close(); stream.destroy() }
  report.decisions = Object.fromEntries(decisions)
  report.findings = Object.fromEntries([...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])))
  return report
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (!process.argv[2]) { console.error('Usage: node audit-summary.js <audit.jsonl>'); process.exitCode = 2 }
  else try { console.log(JSON.stringify(await summarizeAudit(process.argv[2]), null, 2)) }
  catch (error) { console.error(`Audit summary failed: ${error.code || error.name}`); process.exitCode = 2 }
}
