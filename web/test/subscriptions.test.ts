import assert from 'node:assert/strict'
import { test } from 'node:test'
import { api } from '../src/api.ts'
import { api as demo } from '../src/demo/api.ts'
import * as choices from '../src/subscriptions.ts'
import type { SubscriptionSource, SubscriptionStatus } from '../src/types.ts'

const source: SubscriptionSource = { id: 'provider', url: 'https://feeds.example.test/list', send_hwid: true }
const live: SubscriptionStatus = {
  id: 'provider',
  state: 'ready',
  metadata: { title: 'Example provider', announce: '<strong>Service notice</strong>' },
  nodes: [{ id: '11111111111111111111111111111111', name: 'Current exit' }],
}
const labels = {
  auto: 'Auto',
  balance: { 'round-robin': 'Round robin', 'consistent-hash': 'By site', 'sticky-session': 'By session' },
  target: (source: string, node: string) => `${source} / ${node}`,
  unavailable: (name: string) => `${name} (unavailable)`,
}
const subscriptionModes = [
  'subscription:provider:auto', 'subscription:provider:round-robin',
  'subscription:provider:consistent-hash', 'subscription:provider:sticky-session',
]

test('draft target choices use only nodes from the matching source settings', () => {
  const edited = { ...source, url: 'https://feeds.example.test/replacement' }
  const applied = { source, status: live }
  const preview = { source: edited, status: { ...live, nodes: [{ id: '22222222222222222222222222222222', name: 'New exit' }] } }
  const oldChoices = choices.subscriptionRouteChoices(source, choices.draftSubscriptionStatus(source, applied, preview), labels)
  assert.deepEqual(oldChoices.map(choice => choice.value), [...subscriptionModes, 'subscription:provider:11111111111111111111111111111111'])
  const editedChoices = choices.subscriptionRouteChoices(edited, choices.draftSubscriptionStatus(edited, applied), labels)
  assert.deepEqual(editedChoices.map(choice => choice.value), subscriptionModes)
  const previewedChoices = choices.subscriptionRouteChoices(edited, choices.draftSubscriptionStatus(edited, applied, preview), labels)
  assert.deepEqual(previewedChoices.map(choice => choice.value), [...subscriptionModes, 'subscription:provider:22222222222222222222222222222222'])
})

test('an empty applied balance pool labels all three modes unavailable and preserves auto and pins', () => {
  const options = choices.subscriptionRouteChoices(source, { ...live, balance_eligible: 0 }, labels)
  assert.deepEqual(options.map(option => option.label), [
    'Example provider / Auto', 'Example provider / Round robin (unavailable)', 'Example provider / By site (unavailable)',
    'Example provider / By session (unavailable)', 'Example provider / Current exit',
  ])
  assert.ok(options.every(option => !option.disabled && choices.isSubscriptionTarget(option.value)))
  const withoutObservation = choices.subscriptionRouteChoices(source, undefined, labels)
  assert.ok(withoutObservation.every(option => !option.label.includes('(unavailable)')))
})

test('a retired pin remains the selected value without becoming a new choice', () => {
  const options = choices.subscriptionRouteChoices(source, live, labels)
  const retired = 'subscription:provider:33333333333333333333333333333333'
  assert.deepEqual(choices.retainSubscriptionChoice(options, retired, labels.unavailable), [
    ...options, { value: retired, label: 'subscription:provider:33333333333333333333333333333333 (unavailable)', disabled: true },
  ])
  assert.equal(options.some(option => option.value === retired), false)
})

test('pending checks keep the previous HTTPS result visible, including a zero latency', () => {
  const [node] = live.nodes!
  const checkedAt = '2026-11-22T10:00:00Z'
  const checking = { ...node, checking: true, checked_at: checkedAt, latency_ms: 0 }
  assert.equal(choices.subscriptionCheckPending({ ...live, nodes: [checking] }), true)
  assert.deepEqual(choices.subscriptionCheckResult(checking), { at: checkedAt, latency: 0 })
  const failed = { ...node, checked_at: checkedAt, check_error: 'TLS verification failed' }
  assert.deepEqual(choices.subscriptionCheckResult(failed), { at: checkedAt, error: 'TLS verification failed' })
  assert.equal(choices.subscriptionCheckResult(node), undefined)
  assert.equal(choices.subscriptionCheckPending({ ...live, check_progress: { total: 1, completed: 0 } }), true)
  assert.equal(choices.subscriptionCheckPending(live), false)
})

test('preview, refresh, and saved checks use distinct authenticated endpoints', async (t) => {
  const checks: unknown[] = []
  const fetch = t.mock.method(globalThis, 'fetch', async (path: string, init: RequestInit) => {
    assert.equal(init.credentials, 'same-origin')
    switch (`${init.method} ${path}`) {
      case 'POST /api/subscriptions/preview':
        assert.deepEqual(JSON.parse(init.body as string), source)
        return Response.json(live)
      case 'GET /api/subscriptions/status':
        assert.equal(init.body, undefined)
        return Response.json([live])
      case 'POST /api/subscriptions/provider/refresh':
        assert.equal(init.body, undefined)
        return Response.json({ ok: true })
      case 'POST /api/subscriptions/provider/check':
        assert.deepEqual(init.headers, { 'Content-Type': 'application/json' })
        checks.push(JSON.parse(init.body as string))
        return Response.json({ ok: true }, { status: 202 })
      default:
        assert.fail('Unexpected subscription request')
    }
  })
  assert.deepEqual(await api.previewSubscription(source), live)
  assert.deepEqual(await api.subscriptionStatus(), [live])
  assert.deepEqual(await api.refreshSubscription('provider'), { ok: true })
  assert.deepEqual(await api.checkSubscription('provider'), { ok: true })
  assert.deepEqual(await api.checkSubscription('provider', live.nodes![0].id), { ok: true })
  assert.deepEqual(checks, [{}, { node_id: live.nodes![0].id }])
  assert.equal(fetch.mock.callCount(), 5)
})

test('static demo explains that provider actions require the backend', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => assert.fail('Static demo contacted provider'))
  assert.deepEqual(await demo.subscriptionStatus(), [])
  await assert.rejects(demo.previewSubscription(source), { status: 501 })
  await assert.rejects(demo.refreshSubscription('provider'), { status: 501 })
  await assert.rejects(demo.checkSubscription('provider'), { status: 501 })
})

test('provider links use absolute HTTPS URLs without embedded credentials', () => {
  assert.equal(choices.httpsURL('https://support.example.test/path')?.href, 'https://support.example.test/path')
  for (const href of ['http://support.example.test', '//support.example.test', 'javascript:alert(1)', 'data:text/html,notice', 'https://admin:secret@example.test']) {
    assert.equal(choices.httpsURL(href), undefined, href)
  }
})
