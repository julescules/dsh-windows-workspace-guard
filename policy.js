export const POLICY_MODES = new Set(['block', 'ask', 'report'])

export function normalizeMode(mode, reportOnly = false) {
  if (reportOnly) return 'report'
  return POLICY_MODES.has(mode) ? mode : 'block'
}

export function decide(result, mode) {
  if (result.hardBlock) return { kind: 'deny', auditDecision: 'blocked-hard' }
  if (result.status === 'PASS') return { kind: 'allow', auditDecision: 'allowed' }
  if (mode === 'report') return { kind: 'allow', auditDecision: 'reported' }
  if (mode === 'ask') return { kind: 'ask', auditDecision: 'approval-requested' }
  return { kind: 'deny', auditDecision: 'blocked' }
}
