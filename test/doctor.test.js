import assert from 'node:assert/strict'
import test from 'node:test'
import { classifyCredentialAcl, resolveDoctorDshHome, runWindowsGuardDoctor } from '../doctor.js'

test('resolves DSH home deterministically', () => {
  assert.equal(resolveDoctorDshHome({ cwd: 'D:\\work', env: { DSH_HOME: 'D:\\HarnessHome' } }), 'D:\\HarnessHome')
  assert.equal(resolveDoctorDshHome({ cwd: 'D:\\work', env: { USERPROFILE: 'D:\\Users\\Example' } }), 'D:\\Users\\Example\\.dsh')
})

test('classifies readable third-party credential ACL entries without credential contents', () => {
  const result = classifyCredentialAcl({
    currentSid: 'S-1-5-21-100',
    ownerSid: 'S-1-5-21-100',
    rules: [
      { sid: 'S-1-5-21-100', rights: 'FullControl', type: 'Allow', inherited: false },
      { sid: 'S-1-5-21-999', rights: 'ReadAndExecute', type: 'Allow', inherited: true },
      { sid: 'S-1-5-21-888', rights: 'Read', type: 'Deny', inherited: false },
    ],
  })
  assert.deepEqual(result.exposed, [{ sid: 'S-1-5-21-999', rights: 'ReadAndExecute', inherited: true }])
})

test('doctor is bounded and read-only when paths are absent', async () => {
  const missing = async () => { const error = new Error('missing'); error.code = 'ENOENT'; throw error }
  const result = await runWindowsGuardDoctor({
    platform: 'win32',
    osRelease: '10.0.26100',
    dshHome: 'D:\\HarnessHome',
    config: { workspaceRoots: ['D:\\work'], protectedPaths: [], auditPath: '' },
    lstatImpl: missing,
    realpathImpl: missing,
    accessImpl: missing,
    runtimeCandidates: [],
    monotonicGuardAvailable: true,
  })
  assert.equal(result.readOnly, true)
  assert.equal(result.schemaVersion, 'windows-workspace-guard-doctor/v2')
  assert.ok(result.facts.some((item) => item.id === 'monotonic-tool-guard' && item.level === 'PASS'))
  assert.ok(result.facts.some((item) => item.id === 'workspace-path' && item.level === 'WARN'))
  assert.ok(result.facts.some((item) => item.id === 'tool-coverage-pwsh' && item.level === 'PASS'))
  assert.ok(result.facts.some((item) => item.id === 'tool-coverage-read' && item.level === 'PASS'))
  assert.ok(result.facts.some((item) => item.id === 'tool-coverage-write' && item.level === 'PASS'))
  assert.ok(result.facts.some((item) => item.id === 'tool-coverage-edit' && item.level === 'PASS'))
  assert.ok(result.facts.some((item) => item.id === 'tool-coverage-str_replace_editor' && item.level === 'PASS'))
})
