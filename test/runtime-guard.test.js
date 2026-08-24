import assert from 'node:assert/strict'
import test from 'node:test'
import { installMonotonicGuard, monotonicGuardReason } from '../runtime-guard.js'

const config = {
  enabled: true,
  toolNames: ['pwsh'],
  workspaceRoots: ['D:\\work'],
  protectedPaths: [],
  allowExact: [],
  guardGit: true,
  guardSystem: true,
  guardProcesses: true,
  guardNativeEscapes: true,
  guardPersistentShell: true,
  guardSensitiveData: true,
  sensitivePaths: [],
  requireAbsoluteMutationPaths: true,
}

test('returns a final reason only for hard-blocked guarded calls', () => {
  const hard = monotonicGuardReason({ name: 'pwsh', arguments: { command: 'Format-Volume -DriveLetter D', workdir: 'D:\\work' } }, config)
  assert.match(hard, /disk-mutation/)
  assert.equal(monotonicGuardReason({ name: 'pwsh', arguments: { command: 'git push --force', workdir: 'D:\\work' } }, config), undefined)
  assert.equal(monotonicGuardReason({ name: 'other', arguments: { command: 'Format-Volume -DriveLetter D' } }, config), undefined)
})

test('registers the official monotonic guard and keeps an older-host fallback', () => {
  let guard
  const ctx = { tools: { guard(callback) { guard = callback; return () => {} } } }
  const source = { get: () => config }
  const installed = installMonotonicGuard(ctx, source)
  assert.equal(installed.installed, true)
  assert.match(guard({ name: 'pwsh', arguments: { command: 'Get-Content .env', workdir: 'D:\\work' } }), /sensitive-path-read/)
  assert.equal(installMonotonicGuard({ tools: {} }, source).installed, false)
})
