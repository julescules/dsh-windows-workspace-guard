import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const root = new URL('../', import.meta.url)

test('declares the official dsh bundle manifest shape', async () => {
  const pkg = JSON.parse(await readFile(new URL('package.json', root), 'utf8'))
  assert.equal(pkg.dsh.bundle.patch, './cordis.patch.yml')
  assert.equal(pkg.type, 'module')
  assert.equal(pkg.main, 'index.js')
  assert.equal(pkg.version, '0.2.0')
  assert.ok(pkg.files.includes('audit.js'))
  assert.ok(pkg.files.includes('policy.js'))
  assert.equal(pkg.scripts.prepare, undefined)
  assert.ok(pkg.keywords.includes('dsh-plugin'))
})

test('bundle patch mounts the published package name', async () => {
  const patch = await readFile(new URL('cordis.patch.yml', root), 'utf8')
  assert.match(patch, /id:\s*windows-workspace-guard/)
  assert.match(patch, /name:\s*dsh-windows-workspace-guard/)
  assert.match(patch, /mode:\s*block/)
})
