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

test('adapts the official standard-preset read, write, and edit schemas', () => {
  const readSensitive = analyzeToolExecution({
    name: 'read',
    arguments: { file_path: 'D:\\work\\project\\.env', offset: 1, limit: 50 },
  }, options)
  assert.equal(readSensitive.hardBlock, true)
  assert.ok(readSensitive.findings.some((item) => item.id === 'sensitive-path-read'))

  const writeSafe = analyzeToolExecution({
    name: 'write',
    arguments: { file_path: 'D:\\work\\project\\src\\new.txt', content: 'private payload' },
  }, options)
  assert.equal(writeSafe.status, 'PASS')
  assert.equal(writeSafe.mutating, true)
  assert.doesNotMatch(writeSafe.commandPreview, /private payload/)

  const editOutside = analyzeToolExecution({
    name: 'edit',
    arguments: { file_path: 'C:\\outside\\app.js', old_string: 'before', new_string: 'after' },
  }, options)
  assert.equal(editOutside.status, 'FAIL')
  assert.equal(editOutside.hardBlock, true)
  assert.ok(editOutside.findings.some((item) => item.id === 'outside-workspace'))
  assert.doesNotMatch(editOutside.commandPreview, /before|after/)

  const immutable = analyzeToolExecution({
    name: 'write',
    arguments: { file_path: 'D:\\work\\project\\original\\master.txt', content: 'replacement' },
  }, options)
  assert.equal(immutable.hardBlock, true)
  assert.ok(immutable.findings.some((item) => item.id === 'protected-path'))

  const missingPath = analyzeToolExecution({ name: 'read', arguments: { offset: 1 } }, options)
  assert.equal(missingPath.hardBlock, true)
  assert.ok(missingPath.findings.some((item) => item.id === 'unsupported-tool-schema'))
})

test('fails closed for configured tools without a verified schema', () => {
  const result = analyzeToolExecution({ name: 'mystery_writer', arguments: { path: 'D:\\work\\project\\x' } }, options)
  assert.equal(result.hardBlock, true)
  assert.ok(result.findings.some((item) => item.id === 'unsupported-tool-schema'))
  assert.equal(commandForExecution({ name: 'mystery_writer', arguments: {} }), undefined)
})

test('reports coverage without claiming unknown tool schemas are protected', () => {
  assert.deepEqual(coverageFacts({ toolNames: ['pwsh', 'read', 'write', 'edit', 'str_replace_editor', 'custom'] }), [
    { toolName: 'pwsh', adapter: 'powershell-command', covered: true },
    { toolName: 'read', adapter: 'official-filesystem-read', covered: true },
    { toolName: 'write', adapter: 'official-filesystem-write', covered: true },
    { toolName: 'edit', adapter: 'official-filesystem-edit', covered: true },
    { toolName: 'str_replace_editor', adapter: 'structured-file-editor', covered: true },
    { toolName: 'custom', adapter: 'unsupported', covered: false },
  ])
})
