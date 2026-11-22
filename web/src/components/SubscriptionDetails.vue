<script setup lang="ts">
import { computed } from 'vue'
import { NButton } from 'naive-ui'
import { useI18n } from 'vue-i18n'
import { bytes } from '../format'
import { httpsURL, subscriptionCheckResult } from '../subscriptions'
import type { SubscriptionStatus } from '../types'

const props = defineProps<{
  status: SubscriptionStatus
  preview?: boolean
  canCheck?: boolean
  checkingNode?: (nodeId: string) => boolean
}>()
const emit = defineEmits<{ check: [nodeId: string] }>()
const { t, locale } = useI18n()
const metadata = computed(() => props.status.metadata)
const nodes = computed(() => (props.status.nodes ?? []).map(node => {
  const result = subscriptionCheckResult(node)
  return {
    ...node,
    pending: node.checking || props.checkingNode?.(node.id),
    checkedAt: result?.at ? date(result.at) : '',
    result,
  }
}))
const stale = computed(() => !!props.status.last_success && props.status.state !== 'ready')
const support = computed(() => httpsURL(metadata.value?.support_url)?.href)
const profile = computed(() => httpsURL(metadata.value?.profile_url)?.href)

function date(value: string | number): string {
  const time = new Date(value)
  return Number.isFinite(time.getTime()) && time.getUTCFullYear() > 1 ? time.toLocaleString(locale.value) : ''
}

const facts = computed(() => {
  const rows: { label: string; value: string }[] = []
  const { usage, update_interval_hours: interval } = metadata.value ?? {}
  if (usage) {
    if (usage.upload !== undefined) rows.push({ label: t('subscriptions.uploaded'), value: bytes(usage.upload) })
    if (usage.download !== undefined) rows.push({ label: t('subscriptions.downloaded'), value: bytes(usage.download) })
    if (usage.total && usage.total > 0) rows.push({ label: t('subscriptions.allowance'), value: bytes(usage.total) })
    if (usage.expire && usage.expire > 0) rows.push({ label: t('subscriptions.expiry'), value: date(usage.expire * 1000) })
  }
  if (interval) rows.push({ label: t('subscriptions.refreshInterval'), value: t('subscriptions.hours', { n: interval }) })
  const { active_node: active, last_attempt: attempt, last_success: success, last_switch: switched, switch_reason: reason } = props.status
  if (active) rows.push({ label: t('subscriptions.active'), value: nodes.value.find(node => node.id === active)?.name || active })
  if (attempt) rows.push({ label: t('subscriptions.lastAttempt'), value: date(attempt) })
  if (success) rows.push({ label: t('subscriptions.lastSuccess'), value: date(success) })
  if (switched) rows.push({ label: t('subscriptions.lastSwitch'), value: date(switched) })
  if (reason) rows.push({ label: t('subscriptions.switchReason'), value: t('subscriptions.reason.' + reason) })
  return rows.filter(row => row.value)
})
</script>

<template>
  <div class="subscription-details">
    <strong v-if="preview && metadata?.title">{{ metadata.title }}</strong>
    <div class="status-line" role="status">
      <span class="pill" :class="status.state === 'ready' ? 'ok' : status.state === 'pending' ? 'dim' : 'warn'">
        {{ t('subscriptions.state.' + status.state) }}
      </span>
      <span v-if="status.unavailable" class="pill warn">{{ t('subscriptions.autoUnavailable') }}</span>
      <span v-if="status.balance_eligible !== undefined" class="pill" :class="status.balance_eligible ? 'ok' : 'warn'">
        {{ t(status.balance_eligible ? 'subscriptions.balanceEligible' : 'subscriptions.balanceUnavailable', { n: status.balance_eligible }) }}
      </span>
      <span v-if="status.check_progress" class="muted">{{ t('subscriptions.checkProgress', status.check_progress) }}</span>
      <span v-if="status.skipped" class="muted">{{ t('subscriptions.skipped', { n: status.skipped }) }}</span>
    </div>
    <p v-if="status.error" class="muted">{{ status.error }}</p>
    <p v-if="stale" class="muted">{{ t('subscriptions.stale') }}</p>
    <p v-if="metadata?.announce" class="provider-notice">{{ metadata.announce }}</p>
    <div v-if="support || profile" class="provider-links">
      <a v-if="support" :href="support" target="_blank" rel="noopener noreferrer">{{ t('subscriptions.support') }}</a>
      <a v-if="profile" :href="profile" target="_blank" rel="noopener noreferrer">{{ t('subscriptions.profile') }}</a>
    </div>
    <dl v-if="facts.length" class="facts">
      <div v-for="fact in facts" :key="fact.label">
        <dt class="muted">{{ fact.label }}</dt>
        <dd>{{ fact.value }}</dd>
      </div>
    </dl>
    <details v-if="nodes.length">
      <summary>{{ t('subscriptions.nodes', { n: nodes.length }) }}</summary>
      <ul>
        <li v-for="node in nodes" :key="node.id">
          <div>
            <div class="node-title">
              <span>{{ node.name || node.id }}</span>
              <span v-if="node.pending" class="muted" role="status">{{ t('subscriptions.checking') }}</span>
              <span v-else-if="node.health" class="muted">{{ t('subscriptions.health.' + node.health) }}</span>
            </div>
            <div v-if="node.result" class="check-result muted">
              <time v-if="node.checkedAt" :datetime="node.result.at">{{ t('subscriptions.checkedAt', { time: node.checkedAt }) }}</time>
              <span v-if="node.result.latency !== undefined">{{ t('subscriptions.latency', { n: node.result.latency }) }}</span>
              <span v-if="node.result.error">{{ node.result.error }}</span>
            </div>
          </div>
          <NButton
            v-if="canCheck"
            size="small"
            :loading="node.pending"
            :disabled="node.pending"
            :aria-label="t('subscriptions.checkNode', { name: node.name || node.id })"
            @click="emit('check', node.id)"
          >{{ t('subscriptions.check') }}</NButton>
        </li>
      </ul>
    </details>
    <p v-else-if="preview" class="muted">{{ t('subscriptions.nodes', { n: 0 }) }}</p>
  </div>
</template>

<style scoped>
.subscription-details {
  display: grid;
  gap: 10px;
  min-width: 0;
  overflow-wrap: anywhere;
}
.subscription-details p { margin: 0; }
.status-line, .provider-links {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px 14px;
}
.provider-links a { color: var(--accent); }
.provider-notice {
  border-inline-start: 3px solid var(--accent);
  padding-inline-start: 12px;
  white-space: pre-wrap;
}
.facts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 165px), 1fr));
  gap: 10px 16px;
  margin: 0;
}
.facts dd { margin: 0; }
summary { cursor: pointer; }
ul {
  max-height: 240px;
  overflow: auto;
  padding: 0 4px;
  list-style: none;
  margin: 8px 0 0;
}
li {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: start;
  gap: 8px 12px;
  padding: 8px 0;
}
li + li { border-top: 1px solid var(--line); }
.node-title, .check-result {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 10px;
}
.check-result { font-size: 12px; }
</style>
