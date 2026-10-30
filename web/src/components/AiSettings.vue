<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import { fmtDateTime } from '../time.js'
import Icon from './Icon.vue'
import SecretField from './SecretField.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import SettingsSection from './SettingsSection.vue'

const PIDS = ['anthropic', 'openai', 'c1']
const PLACEHOLDER = { anthropic: 'sk-ant-api03-…', openai: 'sk-…', c1: '' }
// Aufgaben in der Reihenfolge der Anzeige; web = nur Modelle mit Websuche
const TASKS = [
  { id: 'classify', label: 'Classify feed advisories', web: false },
  { id: 'research', label: 'Web research', web: true },
  { id: 'verify', label: 'Check high hits with the vendor', web: true },
]
const TASK_NAME = { classify: 'classify', research: 'web research', verify: 'verify' }

const state = ref({ providers: [], tasks: {} })
const keys = reactive({ anthropic: '', openai: '', c1: '' })
const name = ref('')
const baseUrl = ref('')
const choice = reactive({ classify: '', research: '', verify: '' })
const messages = reactive({})
const busy = ref(false)
const tasksMessage = ref(null)
const loadError = ref(null)

// Auswahl nur beim ersten Laden und nach dem Speichern übernehmen, sonst gingen offene Änderungen verloren
async function load(adopt = false) {
  try {
    state.value = await api.get('/api/ai')
    loadError.value = null
    if (adopt) for (const t of TASKS) choice[t.id] = state.value.tasks[t.id]?.ref || ''
  } catch (e) {
    loadError.value = e.message   // nicht als leere Karte stehen lassen
  }
}

const providers = computed(() => state.value.providers)
const anyConfigured = computed(() => providers.value.some((p) => p.configured))
const status = computed(() => (anyConfigured.value ? { tone: 'ok', text: 'Configured' } : { tone: 'neutral', text: 'Not configured' }))

// Referenzen sind „<Anbieter>:<Modell>“; Modell-IDs enthalten selbst Doppelpunkte (Ollama), darum wird nie zerlegt
const refOf = (p, m) => `${p.id}:${m.id}`

function modelLabel(resolved) {
  for (const p of providers.value) {
    const m = p.models.find((x) => refOf(p, x) === resolved)
    if (m) return m.name
  }
  return resolved
}

function groups(task) {
  return providers.value
    .filter((p) => p.configured)
    .map((p) => ({ id: p.id, label: p.label, models: p.models.filter((m) => !task.web || m.web) }))
    .filter((g) => g.models.length)
}

// Gespeicherte Wahl, die es nicht mehr gibt (Anbieter entfernt, Modell verschwunden): sichtbar lassen statt leer anzuzeigen
function stale(task) {
  const ref = choice[task.id]
  if (!ref) return null
  return groups(task).some((g) => g.models.some((m) => `${g.id}:${m.id}` === ref)) ? null : ref
}

function autoText(task) {
  const r = state.value.tasks[task.id]?.resolved
  return r ? `Automatic — currently ${modelLabel(r)}` : 'Automatic — not available'
}

function lastUsed(p) {
  const l = p.last_used
  if (!l) return 'not used yet'
  return `last used ${fmtDateTime(l.at)} with ${l.model} (${TASK_NAME[l.task] || l.task}) — ${l.ok ? 'ok' : `failed${l.error ? `: ${l.error}` : ''}`}`
}

async function act(pid, fn, okText) {
  busy.value = true
  messages[pid] = null
  try {
    const r = await fn()
    messages[pid] = r && r.ok === false ? { kind: 'error', text: `Test failed: ${r.error}` } : { kind: 'ok', text: okText }
    await load()
  } catch (e) {
    messages[pid] = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

function canSave(pid) {
  if (pid !== 'c1') return !!keys[pid].trim()
  const p = providers.value.find((x) => x.id === 'c1')
  return !!(keys.c1.trim() || name.value.trim() || baseUrl.value.trim()) && (p?.configured || !!baseUrl.value.trim())
}

const saveProvider = (pid) => act(pid, async () => {
  const body = {}
  if (keys[pid].trim()) body.api_key = keys[pid].trim()
  if (pid === 'c1') {
    if (name.value.trim()) body.name = name.value.trim()
    if (baseUrl.value.trim()) body.base_url = baseUrl.value.trim()
  }
  await api.put(`/api/ai/providers/${pid}`, body)
  keys[pid] = ''
  if (pid === 'c1') { name.value = ''; baseUrl.value = '' }
}, 'Saved.')

const test = (pid) => act(pid, () => api.post(`/api/ai/providers/${pid}/test`), 'Connection verified successfully.')
const refresh = (pid) => act(pid, () => api.post(`/api/ai/providers/${pid}/refresh`), 'Model list refreshed.')
const clearKey = (pid) => act(pid, () => api.put(`/api/ai/providers/${pid}`, { api_key: '' }), 'API key removed.')
function remove(p) {
  if (!confirm(`Remove ${p.label}? Tasks that use it stop until you pick another model.`)) return
  act(p.id, () => api.del(`/api/ai/providers/${p.id}`), 'Removed.')
}

async function saveTasks() {
  busy.value = true
  tasksMessage.value = null
  try {
    await api.put('/api/ai/tasks', { classify: choice.classify, research: choice.research, verify: choice.verify })
    tasksMessage.value = { kind: 'ok', text: 'Models saved. The next early warning pass uses them.' }
    await load(true)
  } catch (e) {
    tasksMessage.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

onMounted(() => load(true))
</script>

<template>
  <SettingsCard icon="sparkles" title="AI providers" subtitle="Choose which vendor and model vulnwatch uses for each AI task." :status="status">
    <template #intro>
      Used only to read security advisories for the early warning. There is no fallback: if the chosen provider fails,
      the task reports the error and matched advisories wait for review by hand.
      Use dedicated API keys with a strict spend limit.
    </template>

    <p v-if="loadError" class="message error" role="alert" data-test="load-error">
      Could not load the AI settings: {{ loadError }}
      <button type="button" class="btn-sm" data-test="load-retry" @click="load(true)"><Icon name="refresh" :size="14" />Retry</button>
    </p>

    <SettingsSection v-for="p in providers" :key="p.id" :title="p.kind === 'compat' ? 'OpenAI-compatible (Ollama, LM Studio, OpenRouter …)' : p.label">
      <SettingsList :empty="!p.configured" empty-text="Not configured.">
        <SettingsEntry icon="key"
                       :title="p.kind === 'compat' ? `${p.label} · ${p.display_url}` : `${p.label} API key`"
                       :meta="[p.key.set ? `Stored encrypted · changed ${fmtDateTime(p.key.updated_at)} · never shown again` : 'No API key stored', lastUsed(p)]">
          <template #actions>
            <button type="button" class="btn-sm" :data-test="`test-${p.id}`" :disabled="busy" @click="test(p.id)"><Icon name="refresh" :size="14" />Test</button>
            <button type="button" class="btn-sm" :data-test="`refresh-${p.id}`" :disabled="busy" title="Ask the provider for its current model list" @click="refresh(p.id)"><Icon name="refresh" :size="14" />Refresh list</button>
            <button v-if="p.kind === 'compat' && p.key.set" type="button" class="btn-sm" :disabled="busy" @click="clearKey(p.id)"><Icon name="x" :size="14" />Clear key</button>
            <button type="button" class="btn-sm btn-delete" :data-test="`remove-${p.id}`" :disabled="busy" @click="remove(p)"><Icon name="trash" :size="14" />Remove</button>
          </template>
        </SettingsEntry>
      </SettingsList>

      <form class="settings-form" :data-test="`form-${p.id}`" @submit.prevent="saveProvider(p.id)">
        <template v-if="p.kind === 'compat'">
          <label>
            <span class="field-label">Name</span>
            <input v-model="name" name="c1_name" type="text" autocomplete="off" spellcheck="false" :placeholder="p.configured ? p.label : 'Defaults to the host'" />
          </label>
          <label>
            <span class="field-label">Base URL</span>
            <input v-model="baseUrl" name="c1_base_url" type="url" autocomplete="off" spellcheck="false"
                   :placeholder="p.configured ? 'Stored – type a new value to replace it' : 'http://192.168.1.10:11434/v1'" />
          </label>
        </template>
        <SecretField v-model="keys[p.id]" :name="`${p.id}_key`"
                     :label="p.kind === 'compat' ? 'API key (optional)' : (p.key.set ? 'Replace API key' : `${p.label} API key`)"
                     :set="p.key.set" :updated-at="p.key.updated_at" :placeholder="PLACEHOLDER[p.id]"
                     :required="p.kind !== 'compat'" :state="false" />
        <div class="actions">
          <button type="submit" class="primary" :disabled="busy || !canSave(p.id)"><Icon name="check" :size="15" />{{ p.configured ? 'Save changes' : 'Save' }}</button>
        </div>
        <p v-if="messages[p.id]" class="message" :class="messages[p.id].kind" role="status">{{ messages[p.id].text }}</p>
      </form>
    </SettingsSection>

    <SettingsSection v-if="anyConfigured" title="Models per task">
      <div class="task-grid">
        <div v-for="t in TASKS" :key="t.id" class="task-row">
          <label>
            <span class="field-label">{{ t.label }}</span>
            <select v-model="choice[t.id]" :name="`task_${t.id}`" :data-test="`task-${t.id}`">
              <option value="">{{ autoText(t) }}</option>
              <option v-if="stale(t)" :value="stale(t)">{{ stale(t) }} (not available)</option>
              <optgroup v-for="g in groups(t)" :key="g.id" :label="g.label">
                <option v-for="m in g.models" :key="m.id" :value="`${g.id}:${m.id}`">{{ m.name }}</option>
              </optgroup>
            </select>
          </label>
          <p v-if="state.tasks[t.id]?.error" class="text-danger task-error" :data-test="`error-${t.id}`">{{ state.tasks[t.id].error }}</p>
        </div>
      </div>
      <span class="subtext">Web research and the vendor check need a model with web search; compatible endpoints are not offered there.</span>
      <div class="actions">
        <button type="button" class="primary" data-test="save-tasks" :disabled="busy" @click="saveTasks"><Icon name="check" :size="15" />Save models</button>
      </div>
      <p v-if="tasksMessage" class="message" :class="tasksMessage.kind" role="status">{{ tasksMessage.text }}</p>
    </SettingsSection>
  </SettingsCard>
</template>

<style scoped>
.task-grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(min(100%, 280px), 1fr)); }
.task-row { display: flex; flex-direction: column; gap: 0.35rem; }
.task-row label { display: flex; flex-direction: column; gap: 0.35rem; }
.task-error { margin: 0; font-size: 0.82rem; }
</style>
