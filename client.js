window.__ModuleLoader__.load({ id: 'dsh-windows-workspace-guard', factory: (require) => {
  const module = { exports: {} }
  const exports = module.exports
  const React = require('react')
  const { createElement: h, useEffect, useMemo, useState, useSyncExternalStore } = React

  const NAMESPACE = 'windows-workspace-guard'
  const LOCALE = 'settings.windowsWorkspaceGuard'
  const ARRAY_FIELDS = new Set(['toolNames', 'workspaceRoots', 'protectedPaths', 'allowExact', 'sensitivePaths'])
  const EDITABLE_FIELDS = [
    'enabled', 'mode', 'toolNames', 'workspaceRoots', 'protectedPaths', 'allowExact',
    'guardGit', 'guardSystem', 'guardProcesses', 'guardNativeEscapes', 'guardExistingLinks', 'guardSensitiveData', 'sensitivePaths', 'guardPersistentShell', 'requireAbsoluteMutationPaths', 'logDecisions', 'auditPath',
    'auditIncludeCommand', 'auditFailClosed',
  ]
  const zh = {
    title: 'Windows 工作区防护', description: '保护 PowerShell 与官方两套文件工具；未知参数模式默认拒绝。',
    expand: '展开设置', collapse: '收起设置', enabled: '启用防护', mode: '处理模式',
    block: '阻断', ask: '请求一次批准', report: '仅记录', toolNames: '受保护工具名称（已验证：pwsh、read、write、edit、str_replace_editor）',
    workspaceRoots: '可信工作区根（每行一个）', protectedPaths: '不可变保护目录（每行一个）',
    allowExact: '精确允许的命令（每行一个）', guardGit: '检查高风险 Git 操作',
    guardSystem: '硬阻断注册表、WMI/CIM、服务、计划任务、ACL 与链接操作', guardProcesses: '检查进程终止操作',
    guardNativeEscapes: '阻断原生 Shell、脚本宿主与下载落盘绕过',
    guardExistingLinks: '阻断变更目标经过既有 junction/symlink',
    guardSensitiveData: '阻断凭据文件、敏感环境变量读取与外传', sensitivePaths: '额外敏感文件或目录（每行一个）',
    guardPersistentShell: '检查持久 PowerShell 会话状态变更', requireAbsoluteMutationPaths: '文件变更必须使用绝对路径',
    logDecisions: '在控制台记录判定', auditPath: 'JSONL 审计日志路径',
    auditIncludeCommand: '在审计记录中保存脱敏命令预览', auditFailClosed: '审计写入失败时阻断命令',
    save: '保存', saving: '保存中…', reset: '全部恢复部署默认值', saved: '设置已保存并实时生效。',
    failed: '保存失败，请检查值或刷新页面后重试。', readOnly: '当前设置文档为只读。',
  }
  const en = {
    title: 'Windows Workspace Guard', description: 'Protect PowerShell and both official filesystem suites; unknown schemas fail closed.',
    expand: 'Show settings', collapse: 'Hide settings', enabled: 'Enable protection', mode: 'Decision mode',
    block: 'Block', ask: 'Ask once', report: 'Report only', toolNames: 'Guarded tools (verified: pwsh, read, write, edit, str_replace_editor)',
    workspaceRoots: 'Trusted workspace roots (one per line)', protectedPaths: 'Immutable protected paths (one per line)',
    allowExact: 'Exact allowed commands (one per line)', guardGit: 'Inspect risky Git operations',
    guardSystem: 'Hard-block registry, WMI/CIM, service, task, ACL, and link mutations', guardProcesses: 'Inspect process termination',
    guardNativeEscapes: 'Block native shells, script hosts, and download-to-file bypasses',
    guardExistingLinks: 'Block mutation targets that traverse existing junctions/symlinks',
    guardSensitiveData: 'Block credential-file and sensitive-environment reads or exfiltration', sensitivePaths: 'Additional sensitive files or directories (one per line)',
    guardPersistentShell: 'Inspect persistent PowerShell session state', requireAbsoluteMutationPaths: 'Require absolute paths for file mutations',
    logDecisions: 'Log decisions to the console', auditPath: 'JSONL audit log path',
    auditIncludeCommand: 'Store the redacted command preview in audit records', auditFailClosed: 'Block when audit writing fails',
    save: 'Save', saving: 'Saving…', reset: 'Reset all to deployment defaults', saved: 'Settings saved and applied live.',
    failed: 'Save failed. Check the values or refresh and try again.', readOnly: 'The settings document is read-only.',
  }

  const card = { border: '1px solid var(--dsw-alias-border-l1, #d8d8df)', borderRadius: 12, listStyle: 'none', overflow: 'hidden', background: 'var(--dsw-alias-bg-layer-1, #fff)' }
  const header = { width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16, padding: '16px 18px', border: 0, background: 'transparent', color: 'inherit', textAlign: 'left', cursor: 'pointer' }
  const body = { padding: '0 18px 18px', display: 'grid', gap: 14 }
  const grid = { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: 14 }
  const input = { width: '100%', boxSizing: 'border-box', border: '1px solid var(--dsw-alias-border-l2, #bbb)', borderRadius: 8, padding: '8px 10px', color: 'inherit', background: 'var(--dsw-alias-bg-base, #fff)' }
  const button = { border: '1px solid var(--dsw-alias-border-l2, #bbb)', borderRadius: 8, padding: '8px 13px', color: 'inherit', background: 'var(--dsw-alias-bg-layer-2, #f4f4f6)', cursor: 'pointer' }

  function lines(value) {
    return Array.isArray(value) ? value.join('\n') : ''
  }

  function draftOf(value = {}) {
    return {
      enabled: value.enabled !== false,
      mode: typeof value.mode === 'string' ? value.mode : 'block',
      toolNames: lines(value.toolNames?.length ? value.toolNames : ['pwsh', 'read', 'write', 'edit', 'str_replace_editor']),
      workspaceRoots: lines(value.workspaceRoots), protectedPaths: lines(value.protectedPaths), allowExact: lines(value.allowExact),
      guardGit: value.guardGit !== false, guardSystem: value.guardSystem !== false, guardProcesses: value.guardProcesses !== false,
      guardNativeEscapes: value.guardNativeEscapes !== false,
      guardExistingLinks: value.guardExistingLinks !== false,
      guardSensitiveData: value.guardSensitiveData !== false,
      sensitivePaths: lines(value.sensitivePaths),
      guardPersistentShell: value.guardPersistentShell !== false, requireAbsoluteMutationPaths: value.requireAbsoluteMutationPaths !== false,
      logDecisions: value.logDecisions !== false, auditPath: typeof value.auditPath === 'string' ? value.auditPath : '',
      auditIncludeCommand: value.auditIncludeCommand === true, auditFailClosed: value.auditFailClosed === true,
    }
  }

  function parseLines(text) {
    return String(text).split(/\r?\n/).map(value => value.trim()).filter(Boolean)
  }

  function Field({ label, children }) {
    return h('label', { style: { display: 'grid', gap: 6, fontSize: 13 } }, h('span', { style: { fontWeight: 600 } }, label), children)
  }

  function Toggle({ label, checked, disabled, onChange }) {
    return h('label', { style: { display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 } },
      h('input', { type: 'checkbox', checked, disabled, onChange: event => onChange(event.target.checked) }), label)
  }

  function GuardCard(props) {
    const { scope, t } = props
    const snapshot = useSyncExternalStore(listener => scope.subscribe(listener), () => scope.getSnapshot(), () => scope.getSnapshot())
    const valueKey = useMemo(() => JSON.stringify(snapshot.value ?? {}), [snapshot.value])
    const [open, setOpen] = useState(false)
    const [draft, setDraft] = useState(() => draftOf(snapshot.value))
    const [dirty, setDirty] = useState(false)
    const [saving, setSaving] = useState(false)
    const [message, setMessage] = useState('')
    useEffect(() => {
      if (!dirty) setDraft(draftOf(snapshot.value))
    }, [valueKey, dirty])
    if (snapshot.status !== 'ready') return null
    const disabled = !snapshot.writable || saving
    const edit = (field, value) => {
      setDraft(current => ({ ...current, [field]: value }))
      setDirty(true)
      setMessage('')
    }
    const save = async () => {
      setSaving(true); setMessage('')
      try {
        const accepted = snapshot.value ?? {}
        for (const field of EDITABLE_FIELDS) {
          const next = ARRAY_FIELDS.has(field) ? parseLines(draft[field]) : draft[field]
          if (JSON.stringify(accepted[field]) !== JSON.stringify(next)) await scope.set(field, next)
        }
        setDirty(false); setMessage(t('saved'))
      } catch {
        setMessage(t('failed'))
      } finally {
        setSaving(false)
      }
    }
    const reset = async () => {
      setSaving(true); setMessage('')
      try {
        for (const field of EDITABLE_FIELDS) await scope.unset(field)
        setDirty(false); setMessage(t('saved'))
      } catch {
        setMessage(t('failed'))
      } finally {
        setSaving(false)
      }
    }
    const textArea = (field, labelText, rows = 3) => h(Field, { label: labelText }, h('textarea', { style: input, rows, disabled, value: draft[field], onChange: event => edit(field, event.target.value) }))
    return h('li', { style: card },
      h('button', { type: 'button', style: header, 'aria-expanded': open, onClick: () => setOpen(!open) },
        h('span', null, h('strong', { style: { display: 'block', fontSize: 15 } }, t('title')), h('span', { style: { display: 'block', marginTop: 4, opacity: .72, fontSize: 13 } }, t('description'))),
        h('span', null, dirty ? '● ' : '', t(open ? 'collapse' : 'expand'))),
      open ? h('div', { style: body },
        !snapshot.writable ? h('p', { role: 'status' }, t('readOnly')) : null,
        h('div', { style: grid },
          h('div', { style: { display: 'grid', gap: 10 } },
            h(Toggle, { label: t('enabled'), checked: draft.enabled, disabled, onChange: value => edit('enabled', value) }),
            h(Toggle, { label: t('guardGit'), checked: draft.guardGit, disabled, onChange: value => edit('guardGit', value) }),
            h(Toggle, { label: t('guardSystem'), checked: draft.guardSystem, disabled, onChange: value => edit('guardSystem', value) }),
            h(Toggle, { label: t('guardProcesses'), checked: draft.guardProcesses, disabled, onChange: value => edit('guardProcesses', value) }),
            h(Toggle, { label: t('guardNativeEscapes'), checked: draft.guardNativeEscapes, disabled, onChange: value => edit('guardNativeEscapes', value) }),
            h(Toggle, { label: t('guardExistingLinks'), checked: draft.guardExistingLinks, disabled, onChange: value => edit('guardExistingLinks', value) }),
            h(Toggle, { label: t('guardSensitiveData'), checked: draft.guardSensitiveData, disabled, onChange: value => edit('guardSensitiveData', value) }),
            h(Toggle, { label: t('guardPersistentShell'), checked: draft.guardPersistentShell, disabled, onChange: value => edit('guardPersistentShell', value) }),
            h(Toggle, { label: t('requireAbsoluteMutationPaths'), checked: draft.requireAbsoluteMutationPaths, disabled, onChange: value => edit('requireAbsoluteMutationPaths', value) }),
            h(Toggle, { label: t('logDecisions'), checked: draft.logDecisions, disabled, onChange: value => edit('logDecisions', value) }),
            h(Toggle, { label: t('auditIncludeCommand'), checked: draft.auditIncludeCommand, disabled, onChange: value => edit('auditIncludeCommand', value) }),
            h(Toggle, { label: t('auditFailClosed'), checked: draft.auditFailClosed, disabled, onChange: value => edit('auditFailClosed', value) })),
          h('div', { style: { display: 'grid', gap: 12 } },
            h(Field, { label: t('mode') }, h('select', { style: input, disabled, value: draft.mode, onChange: event => edit('mode', event.target.value) },
              h('option', { value: 'block' }, t('block')), h('option', { value: 'ask' }, t('ask')), h('option', { value: 'report' }, t('report')))),
            h(Field, { label: t('auditPath') }, h('input', { style: input, type: 'text', disabled, value: draft.auditPath, onChange: event => edit('auditPath', event.target.value) })),
            textArea('toolNames', t('toolNames'), 2))),
        textArea('workspaceRoots', t('workspaceRoots')), textArea('protectedPaths', t('protectedPaths')), textArea('sensitivePaths', t('sensitivePaths')), textArea('allowExact', t('allowExact'), 4),
        message ? h('p', { role: 'status', style: { margin: 0, fontSize: 13 } }, message) : null,
        h('div', { style: { display: 'flex', justifyContent: 'flex-end', gap: 8 } },
          h('button', { type: 'button', style: button, disabled, onClick: reset }, t('reset')),
          h('button', { type: 'button', style: { ...button, background: 'var(--dsw-alias-brand-primary, #6b5cff)', color: '#fff' }, disabled: disabled || !dirty, onClick: save }, t(saving ? 'saving' : 'save')))) : null)
  }

  exports.name = 'dsh-windows-workspace-guard-client'
  exports.inject = ['slots', 'locale', 'settingsScope']
  exports.apply = function apply(ctx) {
    const scope = ctx.settingsScope.bind({ namespace: NAMESPACE })
    ctx.effect(() => ctx.locale.register(LOCALE, { zh, en }), 'windows-workspace-guard: settings locale')
    ctx.slots.inject('settings.plugin.item', () => ctx.slots.register({
      name: 'settings.plugin.item', key: NAMESPACE, locale: LOCALE, inject: () => ({ scope }),
    }, GuardCard))
  }
  return module.exports
} })
