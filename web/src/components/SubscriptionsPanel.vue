<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { NAlert, NButton, NFormItem, NInput, NModal, NSwitch, useDialog, useMessage } from 'naive-ui'
import { Pencil, Plus, RefreshCw, Trash2 } from '@lucide/vue'
import { useI18n } from 'vue-i18n'
import { api } from '../api'
import { ApiError } from '../apiError'
import { store } from '../store'
import { httpsURL, sameSubscription, subscriptionCheckPending, subscriptionLabel, subscriptionTargetPrefix } from '../subscriptions'
import type { Config, SubscriptionSource, SubscriptionStatus } from '../types'
import SubscriptionDetails from './SubscriptionDetails.vue'

const { t } = useI18n()
const dialog = useDialog()
const message = useMessage()
const refreshing = reactive(new Set<string>())
const checking = reactive(new Set<string>())
const unsupported = ref(!api.subscriptionsAvailable)

const checkKey = (id: string, nodeId = '') => `${id}:${nodeId}`

const rows = computed(() => {
  const sources = new Map<string, { draft?: SubscriptionSource; saved?: SubscriptionSource }>()
  for (const draft of store.state.config?.subscriptions ?? []) sources.set(draft.id, { draft })
  for (const saved of store.applied.value?.subscriptions ?? []) sources.set(saved.id, { ...sources.get(saved.id), saved })
  return [...sources.entries()].map(([id, { draft, saved }]) => {
    const live = store.appliedSubscriptionStatus(id)
    const preview = draft && store.subscriptionPreview(draft)
    const label = saved ? subscriptionLabel(saved, live) : subscriptionLabel(draft!, preview)
    const checkingAll = checking.has(checkKey(id)) || live?.check_progress !== undefined
    return { id, draft, saved, live, preview, label, checkingAll }
  })
})

// The shell polls at its normal cadence. Step up while manual results arrive.
watch(() => !unsupported.value && rows.value.some(row => subscriptionCheckPending(row.live)), (pending, _, cleanup) => {
  if (!pending) return
  const timer = window.setInterval(() => { void store.refreshSubscriptions() }, 1000)
  cleanup(() => window.clearInterval(timer))
}, { immediate: true })

// The modal edits a local copy. A preview is attached to the draft only on Save.
interface Editor {
  config: Config
  source: SubscriptionSource
  original?: SubscriptionSource
  preview?: SubscriptionStatus
  previewing: boolean
  error: string
}

const editor = ref<Editor>()
const showEditor = computed({
  get: () => !!editor.value,
  set: (show: boolean) => { if (!show) editor.value = undefined },
})
const validURL = computed(() => {
  const value = editor.value?.source.url.trim()
  return value && !value.includes('#') && httpsURL(value) ? value : undefined
})

function open(source?: SubscriptionSource) {
  const config = store.state.config
  if (!config || store.state.applying) return
  const id = source?.id ?? 'sub-' + Array.from(crypto.getRandomValues(new Uint8Array(8)), byte => byte.toString(16).padStart(2, '0')).join('')
  editor.value = {
    config,
    source: source ? { ...source } : { id, url: '' },
    original: source,
    preview: source && store.subscriptionPreview(source),
    previewing: false,
    error: '',
  }
}

function updateSource(patch: Partial<SubscriptionSource>) {
  if (!editor.value) return
  Object.assign(editor.value.source, patch)
  editor.value.preview = undefined
  editor.value.error = ''
}

function backendRequired(error: unknown): boolean {
  return error instanceof ApiError && error.status === 501
}

async function preview() {
  const current = editor.value
  if (!current || current.previewing || !validURL.value || unsupported.value) return
  const source = { ...current.source, url: validURL.value }
  current.previewing = true
  current.preview = undefined
  current.error = ''
  try {
    current.preview = await api.previewSubscription(source)
  } catch (error) {
    if (editor.value === current && backendRequired(error)) {
      unsupported.value = true
      current.error = t('subscriptions.backendRequired')
    } else current.error = t('subscriptions.previewFailed')
  } finally {
    current.previewing = false
  }
}

function save() {
  const current = editor.value
  if (!current || !validURL.value || current.previewing || unsupported.value || store.state.applying) return
  const { config, original } = current
  if (store.state.config !== config || (original && !config.subscriptions?.includes(original))) {
    current.error = t('subscriptions.draftChanged')
    return
  }
  const source = { ...current.source, url: validURL.value }
  const list = (config.subscriptions ??= [])
  if (!original) list.push(source)
  else if (!sameSubscription(original, source)) list.splice(list.indexOf(original), 1, source)
  if (current.preview) store.rememberSubscriptionPreview(source, current.preview)
  else store.forgetSubscriptionPreview(source.id)
  editor.value = undefined
}

function remove(source: SubscriptionSource, label: string) {
  const config = store.state.config
  if (!config || store.state.applying) return
  const prefix = subscriptionTargetPrefix(source.id)
  const references = [...(config.groups ?? []), ...(config.clients ?? []), ...(config.networks ?? [])]
    .filter(item => item.target?.startsWith(prefix)).length
  if (references) {
    message.warning(t('subscriptions.inUse', { n: references }))
    return
  }
  dialog.warning({
    title: t('subscriptions.delete'),
    content: t('subscriptions.deleteText', { name: label }),
    positiveText: t('common.delete'),
    negativeText: t('common.cancel'),
    onPositiveClick: () => {
      if (store.state.config !== config || store.state.applying) return
      const sources = config.subscriptions?.filter(item => item !== source)
      if (sources?.length) config.subscriptions = sources
      else delete config.subscriptions
      store.forgetSubscriptionPreview(source.id)
    },
  })
}

// This action refreshes the applied ID even if its source has a pending edit.
async function refresh(id: string) {
  if (refreshing.has(id)) return
  refreshing.add(id)
  try {
    await api.refreshSubscription(id)
    message.success(t('subscriptions.refreshRequested'))
    await store.refreshSubscriptions(true)
  } catch (error) {
    message.error(t(backendRequired(error) ? 'subscriptions.backendRequired' : 'subscriptions.refreshFailed'))
  } finally {
    refreshing.delete(id)
  }
}

// A check uses the applied node catalog and leaves the routing draft untouched.
async function check(id: string, nodeId?: string) {
  const key = checkKey(id, nodeId)
  if (checking.has(key)) return
  checking.add(key)
  try {
    await api.checkSubscription(id, nodeId)
    await store.refreshSubscriptions(true)
  } catch (error) {
    message.error(t(backendRequired(error) ? 'subscriptions.backendRequired' : 'subscriptions.checkFailed'))
  } finally {
    checking.delete(key)
  }
}
</script>

<template>
  <section class="subscriptions" aria-labelledby="subscriptions-heading">
    <div class="section-head">
      <h2 id="subscriptions-heading">{{ t('subscriptions.title') }}</h2>
      <NButton v-if="!unsupported" size="small" secondary :disabled="store.state.applying" @click="open()">
        <template #icon><Plus :size="16" /></template>
        {{ t('subscriptions.add') }}
      </NButton>
    </div>
    <p v-if="unsupported" class="muted">{{ t('subscriptions.backendRequired') }}</p>
    <p v-else-if="!rows.length" class="muted">{{ t('subscriptions.empty') }}</p>
    <NAlert v-if="store.subscriptionStatusFailed.value" type="warning">{{ t('subscriptions.statusFailed') }}</NAlert>
    <article v-for="row in rows" :key="row.id" class="subscription">
      <div class="section-head">
        <div class="source-heading">
          <h3>{{ row.label }}</h3>
          <span v-if="!sameSubscription(row.draft, row.saved)" class="pill warn">
            {{ t(row.draft ? 'subscriptions.pendingApply' : 'subscriptions.pendingRemoval') }}
          </span>
        </div>
        <div class="actions">
          <NButton
            v-if="row.saved && !unsupported && row.live?.nodes?.length"
            size="small"
            :loading="row.checkingAll"
            :disabled="row.checkingAll"
            :aria-label="t('subscriptions.checkAllNodes', { name: row.label })"
            @click="check(row.id)"
          >{{ t('subscriptions.checkAll') }}</NButton>
          <NButton v-if="row.saved" size="small" :loading="refreshing.has(row.id)" @click="refresh(row.id)">
            <template #icon><RefreshCw :size="15" /></template>
            {{ t('subscriptions.refresh') }}
          </NButton>
          <template v-if="row.draft">
            <NButton size="small" :aria-label="t('subscriptions.edit')" :disabled="store.state.applying" @click="open(row.draft)">
              <template #icon><Pencil :size="15" /></template>
            </NButton>
            <NButton size="small" quaternary type="error" :aria-label="t('subscriptions.delete')" :disabled="store.state.applying" @click="remove(row.draft, row.label)">
              <template #icon><Trash2 :size="15" /></template>
            </NButton>
          </template>
        </div>
      </div>
      <SubscriptionDetails
        v-if="row.live"
        :status="row.live"
        :can-check="!!row.saved && !unsupported"
        :checking-node="nodeId => checking.has(checkKey(row.id, nodeId))"
        @check="nodeId => check(row.id, nodeId)"
      />
      <p v-else-if="row.saved" class="muted">{{ t('subscriptions.state.pending') }}</p>
      <template v-if="row.preview && (!row.live || !sameSubscription(row.draft, row.saved))">
        <h4>{{ t('subscriptions.preview') }}</h4>
        <SubscriptionDetails :status="row.preview" :preview="!!row.saved" />
      </template>
    </article>
    <NModal
      v-model:show="showEditor"
      preset="card"
      :title="t(editor?.original ? 'subscriptions.edit' : 'subscriptions.add')"
      class="subscription-modal"
    >
      <template v-if="editor">
        <NFormItem
          :label="t('subscriptions.url')"
          :validation-status="editor.source.url && !validURL ? 'error' : undefined"
          :feedback="editor.source.url && !validURL ? t('subscriptions.invalidURL') : undefined"
        >
          <NInput
            :value="editor.source.url"
            type="password"
            show-password-on="click"
            :placeholder="t('subscriptions.url')"
            :input-props="{ 'aria-label': t('subscriptions.url'), autocomplete: 'off', spellcheck: false }"
            :disabled="editor.previewing"
            @update:value="value => updateSource({ url: value })"
          />
        </NFormItem>
        <label class="hwid-toggle">
          <NSwitch
            :value="!!editor.source.send_hwid"
            :disabled="editor.previewing"
            :aria-label="t('subscriptions.sendHWID')"
            @update:value="value => updateSource({ send_hwid: value })"
          />
          {{ t('subscriptions.sendHWID') }}
        </label>
        <p v-if="editor.source.send_hwid" class="muted">{{ t('subscriptions.hwidHint') }}</p>
        <div class="editor-preview">
          <NAlert v-if="editor.error" type="warning">{{ editor.error }}</NAlert>
          <SubscriptionDetails v-if="editor.preview" :status="editor.preview" preview />
        </div>
      </template>
      <template #action>
        <div class="actions">
          <NButton :disabled="!validURL || unsupported" :loading="editor?.previewing" @click="preview">
            {{ t('subscriptions.preview') }}
          </NButton>
          <NButton quaternary @click="showEditor = false">{{ t('common.cancel') }}</NButton>
          <NButton type="primary" :disabled="!validURL || unsupported || editor?.previewing || store.state.applying" @click="save">
            {{ t('ui.saveDraft') }}
          </NButton>
        </div>
      </template>
    </NModal>
  </section>
</template>

<style scoped>
.subscriptions {
  display: grid;
  gap: 10px;
  margin: 0 0 24px;
  padding: 16px 20px;
  border: 1px solid var(--line);
  border-radius: 10px;
  background: var(--card);
}
.subscriptions h2 { font-size: 20px; }
.subscriptions h2, .subscriptions h3, .subscriptions h4, .subscriptions p { margin: 0; }
.subscription {
  min-width: 0;
  display: grid;
  gap: 12px;
  padding-top: 12px;
  border-top: 1px solid var(--line);
}
.source-heading, .actions, .hwid-toggle {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
.source-heading h3 { overflow-wrap: anywhere; }
.subscription-modal { width: min(580px, calc(100vw - 32px)); }
.subscription-modal p { margin: 8px 0; }
.editor-preview { margin-top: 12px; }
</style>
