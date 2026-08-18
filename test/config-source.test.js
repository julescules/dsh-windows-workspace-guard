import assert from 'node:assert/strict'
import test from 'node:test'
import { createConfigSource, guardedToolNames } from '../config-source.js'

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
  assert.deepEqual([...guardedToolNames({})], ['pwsh'])
  assert.deepEqual([...guardedToolNames({ toolNames: [' PwSh ', 'powershell', 'PWSh', ''] })], ['pwsh', 'powershell'])
})
