import assert from 'node:assert/strict'
import test from 'node:test'
import { commandHash, createAuditRecord } from '../audit.js'
import { decide, normalizeMode } from '../policy.js'

const pass = { status: 'PASS', hardBlock: false }
const review = { status: 'REVIEW', hardBlock: false }
const hard = { status: 'FAIL', hardBlock: true }

test('supports block, ask, and report policy modes', () => {
  assert.equal(decide(pass, 'block').kind, 'allow')
  assert.equal(decide(review, 'block').kind, 'deny')
  assert.equal(decide(review, 'ask').kind, 'ask')
  assert.equal(decide(review, 'report').kind, 'allow')
  assert.equal(decide(hard, 'report').kind, 'deny')
  assert.equal(normalizeMode('invalid'), 'block')
  assert.equal(normalizeMode('ask', true), 'report')
})

test('creates machine-readable audit records without raw secrets by default', () => {
  const command = "$env:API_TOKEN='secret'; git push --force"
  const result = {
    status: 'REVIEW',
    risk: 'HIGH',
    policyVersion: 'test',
    commandPreview: "$env:API_TOKEN=[REDACTED]; git push --force",
    targets: [],
    findings: [{ id: 'git-force-push' }],
  }
  const record = createAuditRecord({ command, cwd: 'D:\\work', result, decision: 'approval-requested' })
  assert.equal(record.commandSha256, commandHash(command))
  assert.equal(record.command, undefined)
  assert.doesNotMatch(JSON.stringify(record), /'secret'/)
  assert.deepEqual(record.findingIds, ['git-force-push'])
})
