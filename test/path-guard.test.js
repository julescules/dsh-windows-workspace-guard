import assert from 'node:assert/strict'
import test from 'node:test'
import { guardAnalysisTargets, inspectExistingPathLinks, windowsPathPrefixes } from '../path-guard.js'

function normalStat() {
  return { isSymbolicLink: () => false }
}

function linkStat() {
  return { isSymbolicLink: () => true }
}

test('builds every lexical prefix for an absolute Windows path', () => {
  assert.deepEqual(windowsPathPrefixes('D:\\work\\project\\link\\file.txt'), [
    'D:\\',
    'D:\\work',
    'D:\\work\\project',
    'D:\\work\\project\\link',
    'D:\\work\\project\\link\\file.txt',
  ])
  assert.deepEqual(windowsPathPrefixes('relative\\file.txt'), [])
})

test('accepts normal existing prefixes and stops at the first missing prefix', async () => {
  const visited = []
  const findings = await inspectExistingPathLinks('D:\\work\\new\\file.txt', {
    lstatImpl: async (prefix) => {
      visited.push(prefix)
      if (prefix === 'D:\\work\\new') throw Object.assign(new Error('missing'), { code: 'ENOENT' })
      return normalStat()
    },
  })
  assert.deepEqual(findings, [])
  assert.deepEqual(visited, ['D:\\', 'D:\\work', 'D:\\work\\new'])
})

test('hard-blocks an existing junction or symbolic-link ancestor', async () => {
  const findings = await inspectExistingPathLinks('D:\\work\\linked\\file.txt', {
    lstatImpl: async (prefix) => prefix === 'D:\\work\\linked' ? linkStat() : normalStat(),
    realpathImpl: async () => 'D:\\outside',
  })
  assert.equal(findings.length, 1)
  assert.equal(findings[0].id, 'existing-reparse-point')
  assert.equal(findings[0].hardBlock, true)
  assert.match(findings[0].evidence, /D:\\work\\linked -> D:\\outside/)
})

test('fails closed when an existing prefix cannot be inspected', async () => {
  const findings = await inspectExistingPathLinks('D:\\work\\file.txt', {
    lstatImpl: async () => { throw Object.assign(new Error('denied'), { code: 'EACCES' }) },
  })
  assert.equal(findings[0].id, 'path-inspection-failed')
  assert.equal(findings[0].hardBlock, true)
})

test('merges live link findings into the static analysis result', async () => {
  const result = {
    policyVersion: 'test', status: 'PASS', risk: 'LOW', mutating: true, destructive: false,
    hardBlock: false, allowedByExact: true, commandPreview: 'Set-Content',
    targets: ['D:\\work\\linked\\file.txt'], findings: [],
  }
  const guarded = await guardAnalysisTargets(result, {
    lstatImpl: async (prefix) => prefix === 'D:\\work\\linked' ? linkStat() : normalStat(),
    realpathImpl: async () => 'D:\\outside',
  })
  assert.equal(guarded.status, 'FAIL')
  assert.equal(guarded.risk, 'CRITICAL')
  assert.equal(guarded.hardBlock, true)
  assert.equal(guarded.allowedByExact, false)
})

test('can explicitly disable live existing-link inspection', async () => {
  const result = { mutating: true, targets: ['D:\\work\\file.txt'], findings: [] }
  assert.equal(await guardAnalysisTargets(result, { enabled: false }), result)
})
