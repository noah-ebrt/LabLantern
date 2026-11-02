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
// Filter je Webhook: keine Auswahl heißt alle Ereignisse bzw. alle Hosts
const EVENTS = [['state_changed', 'State changes'], ['engine_down', 'Checks stopped'], ['engine_up', 'Checks running again']]
const hookEvents = ref([])
const hookHosts = ref('')
const hookBeat = ref(0)
const editing = ref(null)   // Webhook, der gerade geändert wird; URL leer lassen behält sie
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
function resetHook() {
  editing.value = null
  hookName.value = hookUrl.value = hookHosts.value = ''
  hookEvents.value = []
  hookBeat.value = 0
}
function editHook(w) {
  editing.value = w
  hookName.value = w.name
  hookUrl.value = ''
  hookEvents.value = [...w.events]
  hookHosts.value = w.monitors.join(', ')
  hookBeat.value = w.heartbeat_min
}
const saveHook = () => attempt(async () => {
  const body = { name: hookName.value.trim(), url: hookUrl.value.trim(), events: hookEvents.value,
    monitors: hookHosts.value.split(',').map((s) => s.trim()).filter(Boolean), heartbeat_min: Number(hookBeat.value) || 0 }
  if (editing.value) {
    await api.put(`/api/health/webhooks/${editing.value.id}`, body)
    message.value = { kind: 'ok', text: `${body.name} saved.` }
  } else {
    const r = await api.post('/api/health/webhooks', body)
    fresh.value = { kind: 'webhook', name: body.name, value: r.secret }
  }
  resetHook()
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

const hookFilter = (w) => [
  w.events.length ? EVENTS.filter(([k]) => w.events.includes(k)).map(([, l]) => l.toLowerCase()).join(', ') : 'all events',
  w.monitors.length ? `hosts ${w.monitors.join(', ')}` : 'all hosts',
  w.heartbeat_min ? `heartbeat every ${w.heartbeat_min} min` : null].filter(Boolean).join(' · ')
const hookMeta = (w) => [w.target, hookFilter(w), w.last_sent
  ? `${w.last_error ? `failed ${timeAgo(w.last_sent)}: ${w.last_error}` : `${w.last_event || 'delivered'} ${timeAgo(w.last_sent)}`}`
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
      Three ways in: ask now and then, wait for the next change (long-poll, best for status LEDs), or get a webhook.
    </template>

    <SettingsSection title="Endpoints">
      <SettingsList>
        <SettingsEntry dense mono title="GET /api/health/states" meta="compact: {key: state} for microcontrollers, with rev and ETag; add ?hosts=1 for names and critical flags" />
        <SettingsEntry dense mono title="GET /api/health/states?since=<rev>&wait=55" meta="long-poll: answers as soon as something changes, else 304 after the wait; no open port needed" />
        <SettingsEntry dense mono title="GET /api/health/status" meta="full: every host with its checks, latency, age of each result and summary" />
        <SettingsEntry dense mono title="GET /api/health/status/<key>" meta="one host" />
      </SettingsList>
    </SettingsSection>

    <SettingsSection title="Tokens" :count="tokens.length">
      <SettingsList :empty="!tokens.length" empty-text="No device has access yet.">
        <SettingsEntry v-for="t in tokens" :key="t.id" icon="key" :title="t.name"
                       :meta="`created ${fmtStamp(t.created_at)} · last used ${t.last_used ? `${timeAgo(t.last_used)}${t.last_ip ? ` from ${t.last_ip}` : ''}` : 'never'}`">
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
        For servers like Home Assistant or n8n. On every state change vulnwatch POSTs JSON to each URL: <code>changes</code>
        plus the full <code>states</code> as in <code>/api/health/states</code>. Signed with HMAC-SHA256 over
        <code>timestamp.body</code> in <code>X-Vulnwatch-Signature</code>; failed calls are retried after 5 s, 30 s and 2 min.
      </p>
      <SettingsList :empty="!hooks.length" empty-text="No webhook yet.">
        <SettingsEntry v-for="w in hooks" :key="w.id" icon="link" :title="w.name" :meta="hookMeta(w)">
          <template #actions>
            <button type="button" class="btn-sm" @click="testHook(w)"><Icon name="play" :size="14" />Test</button>
            <button type="button" class="btn-sm" @click="editHook(w)"><Icon name="settings" :size="14" />Edit</button>
            <button type="button" class="btn-sm btn-delete" @click="removeHook(w)"><Icon name="trash" :size="14" />Remove</button>
          </template>
        </SettingsEntry>
      </SettingsList>
      <form class="hook-form" @submit.prevent="saveHook">
        <div class="new-row">
          <input v-model="hookName" required maxlength="60" placeholder="Name, e.g. Home Assistant" aria-label="Webhook name" class="hook-name" />
          <input v-model="hookUrl" :required="!editing" type="url" maxlength="2000" aria-label="Webhook URL"
                 :placeholder="editing ? `${editing.target}/… (empty keeps the URL)` : 'http://192.168.1.50/vulnwatch'" />
        </div>
        <div class="new-row options">
          <label v-for="[key, label] in EVENTS" :key="key" class="check"><input v-model="hookEvents" type="checkbox" :value="key" />{{ label }}</label>
          <input v-model="hookHosts" maxlength="2000" placeholder="Only hosts: nas, pve (empty: all)" aria-label="Only these hosts" class="hook-hosts" />
          <label class="check">Heartbeat every <input v-model.number="hookBeat" type="number" min="0" max="1440" aria-label="Heartbeat minutes" class="beat" /> min</label>
          <span class="spacer" />
          <button v-if="editing" type="button" class="btn-sm" @click="resetHook">Cancel</button>
          <button type="submit" class="btn-sm" :disabled="!hookName.trim() || (!editing && !hookUrl.trim())">
            <Icon :name="editing ? 'check' : 'plus'" :size="14" />{{ editing ? 'Save webhook' : 'Add webhook' }}
          </button>
        </div>
        <p class="hint">No event ticked means all of them. A heartbeat (0 = off) lets a receiver notice when vulnwatch itself is gone.</p>
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
.hook-form { display: flex; flex-direction: column; gap: 0.5rem; }
.options { font-size: 0.8125rem; color: var(--text-2); }
.options .hook-hosts { flex: 1 1 200px; }
.options .beat { width: 4.5rem; min-width: 0; flex: none; }
.check { display: inline-flex; align-items: center; gap: 0.35rem; white-space: nowrap; }
.spacer { flex: 1; }
.hint { margin: 0 0 0.5rem; font-size: 0.8125rem; color: var(--text-2); }
.cmd-block { border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--ground); overflow: hidden; }
.cmd-bar-top { display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; padding: 0.25rem 0.5rem 0.25rem 0.75rem; border-bottom: 1px solid var(--line); color: var(--muted); font-size: 0.75rem; }
.cmd-text { margin: 0; padding: 0.75rem; overflow: auto; font: 0.75rem/1.55 var(--mono); color: var(--text-2); white-space: pre; }
</style>
