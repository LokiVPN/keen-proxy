import { computed, reactive, ref, shallowReactive, shallowRef } from 'vue'
import { api } from './api'
import { dnsUpstreamsIncomplete } from './dnsSettings'
import { t } from './i18n'
import type { Config, Device, Status, SubscriptionSource, SubscriptionStatus } from './types'
import { draftSubscriptionStatus, isSubscriptionTarget, retainSubscriptionChoice, sameSubscription, subscriptionRouteChoices, type SubscriptionObservation } from './subscriptions'

// All screens edit this shared draft; Apply sends it in one daemon reload.
const state = reactive({
  config: null as Config | null,
  saved: '',
  status: null as Status | null,
  devices: [] as Device[],
  applying: false,
  error: '',
})

const invalidDNSUpstreams = computed(() => state.config !== null && dnsUpstreamsIncomplete(
  state.config.dns.upstreams,
  state.saved ? (JSON.parse(state.saved) as Config).dns.upstreams : [],
))

const applied = computed(() => (state.saved ? (JSON.parse(state.saved) as Config) : null))
const appliedSources = computed(() => new Map(applied.value?.subscriptions?.map(source => [source.id, source])))
const subscriptionObservations = shallowRef(new Map<string, SubscriptionObservation>())
const subscriptionPreviews = shallowReactive(new Map<string, SubscriptionObservation>())
const subscriptionStatusFailed = ref(false)
let subscriptionRequest: { sources: Map<string, SubscriptionSource>; done: Promise<void> } | undefined

function appliedObservation(id: string): SubscriptionObservation | undefined {
  const observation = subscriptionObservations.value.get(id)
  return sameSubscription(observation?.source, appliedSources.value.get(id)) ? observation : undefined
}

export const authed = ref<boolean | null>(null)

// Records whether the current session entered from a trusted network.
export const session = reactive({ trusted: false, network: '', ip: '' })

// Fill optional collections in place so draft editors can mutate them safely.
// Null is inherit, same as omission. Do not invent an empty system object: that
// would make an untouched older config differ from the saved baseline.
export function normalize(c: Config): Config {
  c.connections ??= []
  c.groups ??= []
  c.networks ??= []
  c.clients ??= []
  c.dns.upstreams ??= []
  for (const g of c.groups) g.entries ??= []
  for (const preset of c.local_presets ?? []) preset.entries ??= []
  c.filters ??= { sources:[],exceptions:[] }
 c.filters.sources ??= []
 c.filters.exceptions ??= []
 c.geoip ??= { databases: [] }
 c.geoip.databases ??= []
  if (c.system == null || c.system.memory_limit_mib == null) {
    if (c.system) delete c.system.memory_limit_mib
    if (!c.system || Object.keys(c.system).length === 0) delete c.system
  }
  return c
}

// Owns the editable draft, last saved snapshot, and daemon status.
export const store = {
  state,
  dirty: computed(() => state.config !== null && JSON.stringify(state.config) !== state.saved),
  applied,
  invalidDNSUpstreams,
  subscriptionStatusFailed,

  appliedSubscriptionStatus(id: string) {
    return appliedObservation(id)?.status
  },
  subscriptionPreview(source: SubscriptionSource) {
    const preview = subscriptionPreviews.get(source.id)
    return sameSubscription(source, preview?.source) ? preview?.status : undefined
  },
  rememberSubscriptionPreview(source: SubscriptionSource, status: SubscriptionStatus) {
    subscriptionPreviews.set(source.id, { source: { ...source }, status })
  },
  forgetSubscriptionPreview(id: string) {
    subscriptionPreviews.delete(id)
  },

  // Replace only the draft; the saved snapshot remains the dirty-state baseline.
  setDraft(c:Config){state.config=normalize(c);state.error=''},

  async load() {
    const cfg = normalize(await api.config())
    state.config = cfg
    state.saved = JSON.stringify(cfg)
    subscriptionRequest = undefined
    subscriptionObservations.value = new Map()
    subscriptionPreviews.clear()
    state.error = ''
    authed.value = true
    await Promise.all([this.refreshStatus(), this.refreshDevices()])
  },

  async loadSession(open = false) {
    const s = await api.session(open)
    session.trusted = s.trusted
    session.network = s.network ?? ''
    session.ip = s.ip
    return s
  },

  async refreshStatus() {
    await Promise.all([
      api.status().then(status => { state.status = status }),
      this.refreshSubscriptions(),
    ])
  },

  // Share polls for the same applied settings. An accepted action needs a later read.
  async refreshSubscriptions(afterAction = false): Promise<void> {
    const sources = appliedSources.value
    if (subscriptionRequest?.sources === sources) {
      await subscriptionRequest.done
      if (afterAction && sources === appliedSources.value) await this.refreshSubscriptions()
      return
    }
    if (!sources.size) {
      if (subscriptionObservations.value.size) subscriptionObservations.value = new Map()
      subscriptionStatusFailed.value = false
      return
    }
    const current = () => subscriptionRequest?.done === request && sources === appliedSources.value
    const request = api.subscriptionStatus().then(statuses => {
      if (!current()) return
      const next = new Map<string, SubscriptionObservation>()
      for (const status of statuses) {
        const source = sources.get(status.id)
        if (source) next.set(status.id, { source, status })
      }
      subscriptionObservations.value = next
      subscriptionStatusFailed.value = false
    }).catch(() => {
      if (current()) subscriptionStatusFailed.value = true
    }).finally(() => {
      if (subscriptionRequest?.done === request) subscriptionRequest = undefined
    })
    subscriptionRequest = { sources, done: request }
    await request
  },

  async refreshDevices() {
    state.devices = await api.devices()
  },

  // Persist the whole draft and advance the baseline only after a successful save.
  async apply() {
    if (!state.config) return
    if (invalidDNSUpstreams.value) throw new Error(t('settings.dnsUpstreamsRequired'))
    state.applying = true
    state.error = ''
    try {
      const cfg = normalize(await api.saveConfig(state.config))
      state.config = cfg
      state.saved = JSON.stringify(cfg)
      subscriptionPreviews.clear()
      await this.refreshStatus()
    } catch (e) {
      state.error = (e as Error).message
      throw e
    } finally {
      state.applying = false
    }
  },

  // Restore a fresh copy of the last saved configuration.
  discard() {
    if (state.saved) state.config = JSON.parse(state.saved)
    subscriptionPreviews.clear()
    state.error = ''
  },
}

function unavailableTarget(name: string) {
  return t('subscriptions.unavailableTarget', { name })
}

const managedTargets = computed(() => (state.config?.subscriptions ?? []).flatMap(source => {
  const status = draftSubscriptionStatus(source, appliedObservation(source.id), subscriptionPreviews.get(source.id))
  return subscriptionRouteChoices(source, status, {
    auto: t('subscriptions.auto'),
    balance: {
      'round-robin': t('subscriptions.balance.round-robin'),
      'consistent-hash': t('subscriptions.balance.consistent-hash'),
      'sticky-session': t('subscriptions.balance.sticky-session'),
    },
    target: (source, node) => t('subscriptions.target', { source, node }),
    unavailable: unavailableTarget,
  })
}))
const managedLabels = computed(() => new Map(managedTargets.value.map(choice => [choice.value, choice.label])))

// Group filters include in-use subscription targets, which can number in the dozens.
export const targets = computed(() => {
  const conns = (state.config?.connections ?? []).map((c) => ({ label: c.name || c.id, value: c.id }))
  const managed = [...new Set((state.config?.groups ?? []).map(group => group.target))]
    .filter(id => isSubscriptionTarget(id) && !conns.some(connection => connection.value === id))
    .map(id => ({ label: targetLabel(id), value: id }))
  return [...conns, ...managed, { label: t('target.direct'), value: 'direct' }, { label: t('target.block'), value: 'block' }]
})

// Resolve built-in and configured targets, preserving unknown IDs for display.
export function targetLabel(id: string | undefined): string {
  if (!id) return '—'
  if (id === 'direct') return t('target.direct')
  if (id === 'block') return t('target.block')
  const c = state.config?.connections?.find((x) => x.id === id)
  if (c) return c.name || c.id
  return managedLabels.value.get(id) ?? (isSubscriptionTarget(id) ? unavailableTarget(id) : id)
}

function connectionChoice(id: string, name: string, disabled: boolean) {
  return { value: id, label: disabled ? t('groups.disabledChoice', { name }) : name }
}

// New choices exclude disabled profiles. The current reference stays visible and labeled.
export function selectableConnections(current?: string | null) {
  return (state.config?.connections ?? [])
    .filter((connection) => !connection.disabled || connection.id === current)
    .map((connection) => connectionChoice(connection.id, connection.name || connection.id, !!connection.disabled))
}

// Full-tunnel policies can use manual and subscription targets.
export function selectableTunnels(current?: string | null) {
  return retainSubscriptionChoice([...selectableConnections(current), ...managedTargets.value], current, unavailableTarget)
}

export function selectableTargets(current?: string | null) {
  return [
    ...selectableTunnels(current),
    { label: t('target.direct'), value: 'direct' },
    { label: t('target.block'), value: 'block' },
  ]
}

export const modeOptions = computed(() => [
  { label: t('mode.split'), value: 'split' },
  { label: t('mode.full'), value: 'full' },
  { label: t('mode.off'), value: 'off' },
])
