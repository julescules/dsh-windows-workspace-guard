import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeToolExecution, commandForExecution, coverageFacts } from '../tool-adapters.js'

const options = {
  cwd: 'D:\\work\\project',
  workspaceRoots: ['D:\\work\\project'],
  protectedPaths: ['D:\\work\\project\\original'],
  guardSensitiveData: true,
  requireAbsoluteMutationPaths: true,
}

test('adapts official str_replace_editor mutations without inspecting file content', () => {
  const safe = analyzeToolExecution({
    name: 'str_replace_editor',
    arguments: { command: 'str_replace', path: 'D:\\work\\project\\src\\app.js', old_str: 'secret source', new_str: 'secret target' },
  }, options)
  assert.equal(safe.status, 'PASS')
  assert.equal(safe.mutating, true)
  assert.doesNotMatch(safe.commandPreview, /secret source|secret target/)

  const outside = analyzeToolExecution({
    name: 'str_replace_editor',
    arguments: { command: 'create', path: 'C:\\Users\\Public\\outside.txt', file_text: 'payload' },
  }, options)
  assert.equal(outside.status, 'FAIL')
  assert.equal(outside.hardBlock, true)
  assert.ok(outside.findings.some((item) => item.id === 'outside-workspace'))
})

test('protects immutable and sensitive paths for structured editor calls', () => {
  const immutable = analyzeToolExecution({
    name: 'str_replace_editor',
    arguments: { command: 'insert', path: 'D:\\work\\project\\original\\master.txt', new_str: 'x' },
  }, options)
  assert.equal(immutable.hardBlock, true)
  assert.ok(immutable.findings.some((item) => item.id === 'protected-path'))

  const sensitive = analyzeToolExecution({
    name: 'str_replace_editor',
    arguments: { command: 'view', path: 'D:\\work\\project\\.env' },
  }, options)
  assert.equal(sensitive.hardBlock, true)
  assert.ok(sensitive.findings.some((item) => item.id === 'sensitive-path-read'))
})

test('fails closed for configured tools without a verified schema', () => {
  const result = analyzeToolExecution({ name: 'mystery_writer', arguments: { path: 'D:\\work\\project\\x' } }, options)
  assert.equal(result.hardBlock, true)
  assert.ok(result.findings.some((item) => item.id === 'unsupported-tool-schema'))
  assert.equal(commandForExecution({ name: 'mystery_writer', arguments: {} }), undefined)
})

test('reports coverage without claiming unknown tool schemas are protected', () => {
  assert.deepEqual(coverageFacts({ toolNames: ['pwsh', 'str_replace_editor', 'custom'] }), [
    { toolName: 'pwsh', adapter: 'powershell-command', covered: true },
    { toolName: 'str_replace_editor', adapter: 'structured-file-editor', covered: true },
    { toolName: 'custom', adapter: 'unsupported', covered: false },
  ])
})
