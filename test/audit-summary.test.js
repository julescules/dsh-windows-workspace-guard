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
  } finally { await rm(dir, { recursive: true, force: true }) }
})
