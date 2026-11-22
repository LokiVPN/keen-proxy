import type { SubscriptionNodeStatus, SubscriptionSource, SubscriptionStatus } from './types'

// Associate observed nodes with the exact settings used to fetch them.
export interface SubscriptionObservation {
  source: SubscriptionSource
  status: SubscriptionStatus
}

type Choice = {
  value: string
  label: string
  disabled?: boolean
}

export const subscriptionBalanceModes = ['round-robin', 'consistent-hash', 'sticky-session'] as const

interface ChoiceLabels {
  auto: string
  balance: Record<(typeof subscriptionBalanceModes)[number], string>
  target: (source: string, node: string) => string
  unavailable: (name: string) => string
}

export function sameSubscription(a?: SubscriptionSource, b?: SubscriptionSource): boolean {
  return !!a && !!b && a.id === b.id && a.url === b.url && !!a.send_hwid === !!b.send_hwid
}

// An applied source uses live data. Edited sources can use a matching preview.
export function draftSubscriptionStatus(source: SubscriptionSource, applied?: SubscriptionObservation, preview?: SubscriptionObservation): SubscriptionStatus | undefined {
  if (applied && sameSubscription(source, applied.source)) return applied.status
  if (preview && sameSubscription(source, preview.source)) return preview.status
}

// Provider links must be absolute HTTPS URLs and may not contain user info.
export function httpsURL(value?: string): URL | undefined {
  const authority = value && /^https:\/\/([^/?#\\\s]+)/i.exec(value)?.[1]
  if (!value || !authority || authority.includes('@') || authority.endsWith(':') || /[\\\s]/.test(value)) return
  try {
    const url = new URL(value)
    if (url.hostname && url.port !== '0') return url
  } catch {
    // Ignore malformed links.
  }
}

// Titles fall back to the host without exposing the source's path or token.
export function subscriptionLabel(source: SubscriptionSource, status?: SubscriptionStatus): string {
  return status?.metadata?.title || httpsURL(source.url)?.hostname || source.id
}

export function subscriptionTargetPrefix(id: string): string {
  return `subscription:${id}:`
}

export function isSubscriptionTarget(id: string): boolean {
  const parts = /^subscription:[a-z0-9_-]{1,64}:([a-z0-9-]{1,32})$/.exec(id)
  if (!parts) return false
  const [, target] = parts
  return target === 'auto' || subscriptionBalanceModes.some(mode => target === mode) || /^[0-9a-f]{32}$/.test(target)
}

// Matching targets use opaque identities even when a provider renames a node.
export function subscriptionRouteChoices(source: SubscriptionSource, status: SubscriptionStatus | undefined, labels: ChoiceLabels): Choice[] {
  const prefix = subscriptionTargetPrefix(source.id)
  const name = subscriptionLabel(source, status)
  const nodes = (status?.nodes ?? []).map(node => {
    const label = labels.target(name, node.name || node.id)
    return { value: prefix + node.id, label: node.health === 'unavailable' ? labels.unavailable(label) : label }
  })
  const auto = labels.target(name, labels.auto)
  const balance = subscriptionBalanceModes.map(mode => {
    const label = labels.target(name, labels.balance[mode])
    return { value: prefix + mode, label: status?.balance_eligible === 0 ? labels.unavailable(label) : label }
  })
  return [{ value: prefix + 'auto', label: status?.unavailable ? labels.unavailable(auto) : auto }, ...balance, ...nodes]
}

// Keep an existing pin (or removed source reference) visible without offering it to new rules.
export function retainSubscriptionChoice(choices: Choice[], current: string | null | undefined, unavailable: ChoiceLabels['unavailable']): Choice[] {
  if (!current || !isSubscriptionTarget(current) || choices.some(choice => choice.value === current)) return choices
  return [...choices, { value: current, label: unavailable(current), disabled: true }]
}

// Full and individual checks both need status polling while pending.
export function subscriptionCheckPending(status?: SubscriptionStatus): boolean {
  return status?.check_progress !== undefined || status?.nodes?.some(node => node.checking) === true
}

// Use the completed result independently of any check currently in progress.
export function subscriptionCheckResult(node: SubscriptionNodeStatus): { at?: string; latency?: number; error?: string } | undefined {
  const { checked_at: at, latency_ms: latency, check_error: error } = node
  if (error) return { at, error }
  if (latency !== undefined) return { at, latency }
  if (at) return { at }
}
