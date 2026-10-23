import assert from 'node:assert/strict'
import { Context } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import Settings from '@deepseek-ai/dsh-settings'
import Tools from '@deepseek-ai/dsh-tools'
import * as guard from '../index.js'

const ctx = new Context()
const loader = new Loader(ctx)
loader.builtins.guard = guard
ctx.provide('systemPrompt', { tools() {} })
ctx.provide('profileContext', { home: new URL('./tmp/profile', import.meta.url).pathname, name: 'contract-test' })
ctx.provide('configEditor', {
  documentPath: 'in-memory-contract-test',
  entries: () => [...loader.entries()],
  configuration: () => [...loader.entries()].map(entry => ({ entry, inherited: {}, override: entry.options.config ?? {} })),
  async edit(entry, change) {
    const next = change(entry.options.config ?? {}, {})
    // Validate before updating, as the host editor does.
    guard.Config(next)
    await entry.update({ config: next })
  },
})
const fibers = []
try {
  fibers.push(await ctx.plugin(Tools))
  fibers.push(await ctx.plugin(Settings))
  await loader.root.update([{ id: 'windows-workspace-guard', name: 'cordis:guard', config: { workspaceRoots: ['D:\\allowed'], guardExistingLinks: false, logDecisions: false } }])
  await loader.await()
  const entry = loader.resolve('windows-workspace-guard')
  assert.equal(entry.fiber.state, 2)
  const originalFiber = entry.fiber
  const descriptor = () => ctx.settings.describe().find(row => row.ns === 'windows-workspace-guard')
  assert.equal(descriptor().autoGenerate, true)
  assert.equal(descriptor().value.mode, 'block')
  const formSchema = descriptor().schema
  assert.ok(formSchema.refs[formSchema.uid].dict.workspaceRoots)
  const tool = ctx.tools.get('windows_workspace_guard_check')
  assert.ok(tool)
  async function check(path) {
    const result = await tool.execute({ toolName: 'write', path, cwd: 'D:\\allowed' }, {})
    return JSON.parse(JSON.stringify(result))
  }
  const initial = await check('D:\\outside\\new.txt')
  assert.equal(initial.hardBlock, true)
  const revision = descriptor().revision
  await ctx.settings.update('windows-workspace-guard', { workspaceRoots: ['D:\\outside'], mode: 'ask' }, revision)
  assert.equal(entry.fiber, originalFiber, 'live settings must not remount')
  assert.equal(descriptor().value.mode, 'ask')
  assert.equal((await check('D:\\outside\\new.txt')).hardBlock, false)
  await assert.rejects(ctx.settings.update('windows-workspace-guard', { mode: 'report' }, revision), { code: 'SETTINGS_CONFLICT' })
  await assert.rejects(ctx.settings.update('windows-workspace-guard', { mode: 'invalid-mode' }))
  assert.equal(descriptor().value.mode, 'ask')
  console.log('PASS: rc.3 actual Loader/Settings/Tools; generated form, live roots/mode, unchanged fiber, stale revision rejection, invalid mode rejection. Profile editor adapter is in-memory; browser/model not tested.')
} finally {
  loader.root.stop()
  await loader.await()
  for (const fiber of fibers.reverse()) await fiber.dispose()
}
