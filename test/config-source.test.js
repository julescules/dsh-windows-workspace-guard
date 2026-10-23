import assert from 'node:assert/strict'
import test from 'node:test'
import { createConfigSource, guardedToolNames } from '../config-source.js'

test('reads replacement volatile values without retaining startup policy', () => {
  let value = { enabled: true, mode: 'block', workspaceRoots: ['D:\\old'] }
  const source = createConfigSource({ get: () => value })
  assert.equal(source.get().mode, 'block')
  value = { enabled: true, mode: 'ask', workspaceRoots: ['D:\\new'] }
  assert.equal(source.get().mode, 'ask')
  assert.deepEqual(source.get().workspaceRoots, ['D:\\new'])
})

test('switches from startup config to the live settings source', () => {
  const startup = { enabled: true, mode: 'block' }
  const live = { enabled: true, mode: 'ask' }
  const source = createConfigSource(startup)

  assert.equal(source.get(), startup)
  source.setSource(() => live)
  assert.equal(source.get(), live)
  assert.throws(() => source.setSource(undefined), /configuration source/)
  assert.equal(source.get(), live)
})

test('normalizes configurable intercepted tool names', () => {
  assert.deepEqual([...guardedToolNames({})], ['pwsh', 'read', 'read_image', 'write', 'edit', 'glob', 'grep', 'str_replace_editor'])
  assert.deepEqual([...guardedToolNames({ toolNames: [' PwSh ', 'powershell', 'PWSh', ''] })], ['pwsh', 'powershell'])
})
