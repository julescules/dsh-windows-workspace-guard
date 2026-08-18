import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import vm from 'node:vm'

test('ships an official lazy-CJS settings-card artifact', async () => {
  const source = await readFile(new URL('../client.js', import.meta.url), 'utf8')
  let registration
  const sandbox = {
    window: {
      __ModuleLoader__: {
        load(value) { registration = value },
      },
    },
  }
  vm.runInNewContext(source, sandbox, { filename: 'client.js' })
  assert.equal(registration.id, 'dsh-windows-workspace-guard')
  assert.equal(typeof registration.factory, 'function')

  const react = {
    createElement() {},
    useEffect() {},
    useMemo() {},
    useState() {},
    useSyncExternalStore() {},
  }
  const client = registration.factory((name) => {
    assert.equal(name, 'react')
    return react
  })

  assert.equal(client.name, 'dsh-windows-workspace-guard-client')
  assert.deepEqual([...client.inject], ['slots', 'locale', 'settingsScope'])

  const registered = {}
  const boundScope = { marker: 'bound' }
  const ctx = {
    effect(callback) { callback() },
    locale: {
      register(namespace, value) { registered.locale = { namespace, value } },
    },
    settingsScope: {
      bind(options) { registered.bind = options; return boundScope },
    },
    slots: {
      inject(name, callback) {
        registered.slot = name
        callback()
      },
      register(options, component) { registered.card = { options, component } },
    },
  }
  client.apply(ctx)

  assert.equal(registered.bind.namespace, 'windows-workspace-guard')
  assert.equal(registered.slot, 'settings.plugin.item')
  assert.equal(registered.card.options.key, 'windows-workspace-guard')
  assert.equal(typeof registered.card.component, 'function')
  assert.equal(registered.locale.namespace, 'settings.windowsWorkspaceGuard')
})
