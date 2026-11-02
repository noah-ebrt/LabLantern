<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { fmtStamp, timeAgo } from '../time.js'
import Icon from './Icon.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import SettingsSection from './SettingsSection.vue'

// Andere Geräte (ESP-Statusleiste, Home Assistant, Skripte): Nur-Lese-Token zum Abfragen, Webhooks für Push bei Wechseln
const tokens = ref([])
const hooks = ref([])
const name = ref('')
const hookName = ref('')
const hookUrl = ref('')
// Geheimnis direkt nach dem Anlegen, nur bis zum Neuladen sichtbar: { kind: 'token' | 'webhook', name, value }
const fresh = ref(null)
const copied = ref(false)
const message = ref(null)

async function load() {
  ;[tokens.value, hooks.value] = await Promise.all([api.get('/api/health/tokens'), api.get('/api/health/webhooks')])
}
async function attempt(fn) {
  message.value = null
  try {
    await fn()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  }
}
const create = () => attempt(async () => {
  const r = await api.post('/api/health/tokens', { name: name.value.trim() })
  fresh.value = { kind: 'token', name: name.value.trim(), value: r.token }
  name.value = ''
  await load()
})
const addHook = () => attempt(async () => {
  const r = await api.post('/api/health/webhooks', { name: hookName.value.trim(), url: hookUrl.value.trim() })
  fresh.value = { kind: 'webhook', name: hookName.value.trim(), value: r.secret }
  hookName.value = hookUrl.value = ''
  await load()
})
const testHook = (w) => attempt(async () => {
  const r = await api.post(`/api/health/webhooks/${w.id}/test`, {})
  message.value = r.ok ? { kind: 'ok', text: `Test sent to ${w.name}.` } : { kind: 'error', text: `${w.name}: ${r.error}` }
  await load()
})
async function revoke(t) {
  if (!confirm(`Revoke the token “${t.name}”? Devices using it get 401 from then on.`)) return
  await api.del(`/api/health/tokens/${t.id}`)
  await load()
}
async function removeHook(w) {
  if (!confirm(`Remove the webhook “${w.name}”? It gets no more changes.`)) return
  await api.del(`/api/health/webhooks/${w.id}`)
  await load()
}

const hookMeta = (w) => [w.target, w.last_sent
  ? `${w.last_error ? `failed ${timeAgo(w.last_sent)}: ${w.last_error}` : `delivered ${timeAgo(w.last_sent)}`}`
  : `added ${fmtStamp(w.created_at)} · nothing sent yet`]
const status = computed(() => {
  const n = tokens.value.length + hooks.value.length
  if (hooks.value.some((w) => w.last_error)) return { tone: 'warning', text: 'Webhook failing' }
  return n ? { tone: 'ok', text: `${tokens.value.length} token${tokens.value.length === 1 ? '' : 's'} · ${hooks.value.length} webhook${hooks.value.length === 1 ? '' : 's'}` }
    : { tone: 'neutral', text: 'No access yet' }
})

async function copy() {
  try {
    await navigator.clipboard.writeText(fresh.value.value)
    copied.value = true
    setTimeout(() => (copied.value = false), 2500)
  } catch {
    message.value = { kind: 'error', text: 'Copying needs a secure context – select the text and copy it by hand.' }
  }
}
onMounted(load)
</script>

<template>
  <SettingsCard icon="key" title="API for other devices" subtitle="Status LEDs, Home Assistant or scripts read the health of every host" :status="status">
    <template #intro>
      Read-only: a token can read states but change nothing, a webhook only receives. Create one per device, so you can revoke it on its own.
      If health checks stop, the API answers <code>"unknown"</code> and <code>"engine_ok": false</code> instead of an outdated “up”.
    </template>

    <SettingsSection title="Endpoints">
      <SettingsList>
        <SettingsEntry dense mono title="GET /api/health/states" meta="compact: {key: state} for microcontrollers" />
        <SettingsEntry dense mono title="GET /api/health/status" meta="full: every host with its checks, latency, age of each result and summary" />
        <SettingsEntry dense mono title="GET /api/health/status/<key>" meta="one host" />
      </SettingsList>
    </SettingsSection>

    <SettingsSection title="Tokens" :count="tokens.length">
      <SettingsList :empty="!tokens.length" empty-text="No device has access yet.">
        <SettingsEntry v-for="t in tokens" :key="t.id" icon="key" :title="t.name"
                       :meta="`created ${fmtStamp(t.created_at)} · last used ${t.last_used ? timeAgo(t.last_used) : 'never'}`">
          <template #actions><button type="button" class="btn-sm btn-delete" @click="revoke(t)"><Icon name="trash" :size="14" />Revoke</button></template>
        </SettingsEntry>
      </SettingsList>
      <form class="new-row" @submit.prevent="create">
        <input v-model="name" required maxlength="60" placeholder="Device, e.g. Status LED shelf" aria-label="Token name" />
        <button type="submit" class="btn-sm" :disabled="!name.trim()"><Icon name="plus" :size="14" />Create token</button>
      </form>
    </SettingsSection>

    <SettingsSection title="Webhooks" :count="hooks.length">
      <p class="hint">
        On every state change vulnwatch POSTs JSON to each URL: <code>changes</code> plus the full <code>states</code> as in
        <code>/api/health/states</code>. Signed with HMAC-SHA256 over the body in <code>X-Vulnwatch-Signature: sha256=…</code>.
      </p>
      <SettingsList :empty="!hooks.length" empty-text="No webhook yet.">
        <SettingsEntry v-for="w in hooks" :key="w.id" icon="link" :title="w.name" :meta="hookMeta(w)">
          <template #actions>
            <button type="button" class="btn-sm" @click="testHook(w)"><Icon name="play" :size="14" />Test</button>
            <button type="button" class="btn-sm btn-delete" @click="removeHook(w)"><Icon name="trash" :size="14" />Remove</button>
          </template>
        </SettingsEntry>
      </SettingsList>
      <form class="new-row" @submit.prevent="addHook">
        <input v-model="hookName" required maxlength="60" placeholder="Name, e.g. Status LED shelf" aria-label="Webhook name" class="hook-name" />
        <input v-model="hookUrl" required type="url" maxlength="2000" placeholder="http://192.168.1.50/vulnwatch" aria-label="Webhook URL" />
        <button type="submit" class="btn-sm" :disabled="!hookName.trim() || !hookUrl.trim()"><Icon name="plus" :size="14" />Add webhook</button>
      </form>
    </SettingsSection>

    <div v-if="fresh" class="cmd-block">
      <div class="cmd-bar-top">
        <span>{{ fresh.kind === 'token' ? 'Token' : 'Signing key' }} for {{ fresh.name }} · shown only now</span>
        <button type="button" class="btn-sm" @click="copy"><Icon :name="copied ? 'check' : 'copy'" :size="14" />{{ copied ? 'Copied' : 'Copy' }}</button>
      </div>
      <pre class="cmd-text">{{ fresh.value }}</pre>
    </div>
    <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
  </SettingsCard>
</template>

<style scoped>
.new-row { display: flex; flex-direction: row; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
.new-row input { flex: 1; min-width: 200px; }
.new-row .hook-name { flex: 0 1 220px; }
.new-row button { flex: none; }
.hint { margin: 0 0 0.5rem; font-size: 0.8125rem; color: var(--text-2); }
.cmd-block { border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--ground); overflow: hidden; }
.cmd-bar-top { display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; padding: 0.25rem 0.5rem 0.25rem 0.75rem; border-bottom: 1px solid var(--line); color: var(--muted); font-size: 0.75rem; }
.cmd-text { margin: 0; padding: 0.75rem; overflow: auto; font: 0.75rem/1.55 var(--mono); color: var(--text-2); white-space: pre; }
</style>
