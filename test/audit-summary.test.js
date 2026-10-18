import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { summarizeAudit } from '../audit-summary.js'

test('aggregate repeated findings without exporting command or path data; report incomplete evidence', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'guard-summary-'))
  try {
    const file = path.join(dir, 'audit.jsonl')
    await writeFile(file, JSON.stringify({ decision: 'block', findingIds: ['secret-path', 'secret-path'], command: 'PRIVATE_VALUE', cwd: 'PRIVATE_PATH' }) + '\n{broken\n' + JSON.stringify({ decision: 'allow', findingIds: [] }) + '\n')
    const result = await summarizeAudit(file)
    assert.equal(result.records, 2)
    assert.equal(result.decisions.other, 2)
    assert.equal(result.malformed, 1)
    assert.equal(result.findings['secret-path'], 1)
    assert.ok(!JSON.stringify(result).includes('PRIVATE'))
    assert.equal((await summarizeAudit(file, { maxRecords: 1 })).truncated, true)
    await assert.rejects(summarizeAudit(file, { maxBytes: 1 }), { code: 'AUDIT_SIZE_LIMIT' })
    await assert.rejects(summarizeAudit(file, { maxRecords: 0 }), RangeError)
  } finally { await rm(dir, { recursive: true, force: true }) }
})

test('time and decision filters count scanned evidence and preserve record limits', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'guard-summary-'))
  try {
    const file = path.join(dir, 'audit.jsonl')
    const rows = [
      { ts: '2026-10-17T23:59:59Z', decision: 'blocked-hard', findingIds: ['old'] },
      { ts: '2026-10-18T01:00:00+01:00', decision: 'blocked-hard', findingIds: ['boundary'] },
      { ts: '2026-10-18T01:00:00Z', decision: 'allowed', findingIds: [] },
      { ts: 'invalid', decision: 'blocked-hard', findingIds: ['bad-time'] },
      { ts: '2026-10-19T00:00:00Z', decision: 'blocked-hard', findingIds: ['future'] },
    ]
    await writeFile(file, rows.map(row => JSON.stringify(row)).join('\n'))
    const options = { since: '2026-10-18T00:00:00Z', until: '2026-10-18T23:59:59Z', decision: 'blocked-hard' }
    const result = await summarizeAudit(file, options)
    assert.equal(result.records, 5)
    assert.equal(result.matched, 1)
    assert.equal(result.excluded, 4)
    assert.equal(result.invalidTimestamps, 1)
    assert.deepEqual(result.findings, { boundary: 1 })
    const limited = await summarizeAudit(file, { ...options, maxRecords: 1 })
    assert.equal(limited.matched, 0)
    assert.equal(limited.truncated, true)
    for (const invalid of [{ since: '2026-10-18' }, { since: '2026-02-30T00:00:00Z' }, { since: '2026-10-18T24:00:00Z' }, { since: options.until, until: options.since }, { decision: 'typo' }]) {
      await assert.rejects(summarizeAudit(file, invalid), RangeError)
    }
    assert.equal((await summarizeAudit(file)).matched, 5)
  } finally { await rm(dir, { recursive: true, force: true }) }
})
