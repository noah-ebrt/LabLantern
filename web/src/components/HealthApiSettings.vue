<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { fmtStamp, timeAgo } from '../time.js'
import Icon from './Icon.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import SettingsSection from './SettingsSection.vue'

// Nur-Lese-Zugang für andere Geräte (ESP-Statusleiste, Home Assistant, Skripte): ein Token je Gerät
const props = defineProps({ monitors: { type: Array, required: true } })
const tokens = ref([])
const name = ref('')
const created = ref(null)
const copied = ref('')
const message = ref(null)
const origin = window.location.origin

async function load() {
  tokens.value = await api.get('/api/health/tokens')
}
async function create() {
  message.value = null
  try {
    const r = await api.post('/api/health/tokens', { name: name.value.trim() })
    created.value = { name: name.value.trim(), token: r.token }
    name.value = ''
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  }
}
async function revoke(t) {
  if (!confirm(`Revoke the token “${t.name}”? Devices using it get 401 from then on.`)) return
  await api.del(`/api/health/tokens/${t.id}`)
  await load()
}

const tok = computed(() => created.value?.token || '<token>')
const example = computed(() => props.monitors[0]?.slug || 'nas')
const curl = computed(() => `curl -s --cacert vulnwatch-ca.crt -H "Authorization: Bearer ${tok.value}" \\
  ${origin}/api/health/states

# {"engine_ok": true, "states": {"${example.value}": "up", …}, "critical": […]}`)
const esp = computed(() => `// ESP32 (Arduino): CA from ${origin}/ca.crt
WiFiClientSecure tls;  tls.setCACert(VULNWATCH_CA);
HTTPClient http;
http.begin(tls, "${origin}/api/health/states");
http.addHeader("Authorization", "Bearer ${tok.value}");
if (http.GET() == 200) {
  JsonDocument doc;  deserializeJson(doc, http.getStream());
  bool fresh = doc["engine_ok"];                 // false: show "no data", never green
  const char* nas = doc["states"]["${example.value}"];  // up | degraded | down | unknown | paused
}`)

async function copy(text, which) {
  try {
    await navigator.clipboard.writeText(text)
    copied.value = which
    setTimeout(() => (copied.value = ''), 2500)
  } catch {
    message.value = { kind: 'error', text: 'Copying needs a secure context – select the text and copy it by hand.' }
  }
}
onMounted(load)
</script>

<template>
  <SettingsCard icon="key" title="API for other devices" subtitle="Status LEDs, Home Assistant or scripts read the health of every host"
                :status="tokens.length ? { tone: 'ok', text: `${tokens.length} token${tokens.length > 1 ? 's' : ''}` } : { tone: 'neutral', text: 'No token yet' }">
    <template #intro>
      Read-only: a token can read states but change nothing. Create one per device, so you can revoke it on its own. If health checks stop,
      the API answers <code>"unknown"</code> and <code>"engine_ok": false</code> instead of an outdated “up”.
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
      <form class="new-token" @submit.prevent="create">
        <input v-model="name" required maxlength="60" placeholder="Device, e.g. Status LED shelf" aria-label="Token name" />
        <button type="submit" class="btn-sm" :disabled="!name.trim()"><Icon name="plus" :size="14" />Create token</button>
      </form>
    </SettingsSection>

    <div class="cmd-block">
      <div class="cmd-bar-top">
        <span>{{ created ? `Token for ${created.name} · shown only now` : 'Example request' }}</span>
        <button type="button" class="btn-sm" @click="copy(curl, 'curl')"><Icon :name="copied === 'curl' ? 'check' : 'copy'" :size="14" />{{ copied === 'curl' ? 'Copied' : 'Copy' }}</button>
      </div>
      <pre class="cmd-text">{{ curl }}</pre>
    </div>
    <details class="esp">
      <summary>ESP32 status LED example</summary>
      <div class="cmd-block">
        <div class="cmd-bar-top">
          <span>Arduino · HTTPClient + ArduinoJson</span>
          <button type="button" class="btn-sm" @click="copy(esp, 'esp')"><Icon :name="copied === 'esp' ? 'check' : 'copy'" :size="14" />{{ copied === 'esp' ? 'Copied' : 'Copy' }}</button>
        </div>
        <pre class="cmd-text">{{ esp }}</pre>
      </div>
    </details>
    <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
  </SettingsCard>
</template>

<style scoped>
.new-token { display: flex; flex-direction: row; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
.new-token input { flex: 1; min-width: 200px; }
.new-token button { flex: none; }
.esp summary { cursor: pointer; font-size: 0.84rem; color: var(--text-2); margin-bottom: 0.6rem; }
.cmd-block { border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--ground); overflow: hidden; }
.cmd-bar-top { display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; padding: 0.35rem 0.5rem 0.35rem 0.8rem; border-bottom: 1px solid var(--line); color: var(--muted); font-size: 0.75rem; }
.cmd-text { margin: 0; padding: 0.75rem 0.85rem; overflow: auto; font: 0.76rem/1.55 var(--mono); color: var(--text-2); white-space: pre; }
</style>
