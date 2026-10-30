<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { fmtDateTime } from '../time.js'
import Icon from './Icon.vue'
import SecretField from './SecretField.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import SettingsSection from './SettingsSection.vue'

const state = ref({ configured: false, api_key: { set: false, updated_at: null }, model: '', selected: null, auto_model: '', last_used: null })
// Modelle kommen von Anthropic selbst (24 h zwischengespeichert); leer = automatisch das neueste Haiku
const models = ref([])
const choice = ref('')
const key = ref('')
const message = ref(null)
const busy = ref(false)

async function load() {
  state.value = await api.get('/api/integrations/claude')
  choice.value = state.value.selected || ''
  if (state.value.api_key.set) models.value = (await api.get('/api/integrations/claude/models').catch(() => ({ items: [] }))).items
}

async function refreshModels() {
  models.value = (await api.get('/api/integrations/claude/models?refresh=true')).items
}

const saveModel = () => act(() => api.put('/api/integrations/claude/model', { model: choice.value || null }),
  'Model saved. The next early warning pass uses it.')
const lastUsed = computed(() => {
  const l = state.value.last_used
  if (!l) return 'not used yet'
  return `last used ${fmtDateTime(l.at)} with ${l.model}${l.ok ? '' : ' (failed)'}`
})

async function act(fn, okText) {
  busy.value = true
  message.value = null
  try {
    const r = await fn()
    message.value = r && r.ok === false ? { kind: 'error', text: `Test failed: ${r.error}` } : { kind: 'ok', text: okText }
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

const save = () => act(async () => {
  await api.put('/api/integrations/claude', { api_key: key.value.trim() })
  key.value = ''
}, 'API key saved.')

const test = () => act(() => api.post('/api/integrations/claude/test'), 'API connection verified successfully.')
const remove = () => {
  if (!confirm('Remove the Claude API key? Early warnings then wait for review by hand.')) return
  act(() => api.del('/api/integrations/claude'), 'API key removed.')
}
const status = computed(() => (state.value.api_key.set ? { tone: 'ok', text: 'Configured' } : { tone: 'neutral', text: 'Not configured' }))

onMounted(load)
</script>

<template>
  <SettingsCard icon="sparkles" title="Claude AI Integration" subtitle="AI-assisted vulnerability impact analysis and zero-day threat assessments" :status="status">
    <template #intro>
      Used only to read security advisories for the early warning (now <code>{{ state.model || 'claude-haiku-5-5' }}</code>).
      Use a dedicated Anthropic API key with a strict spend limit.
    </template>

    <SettingsSection title="API key">
      <SettingsList :empty="!state.api_key.set" empty-text="No API key stored. Matched advisories wait for review by hand until you add one.">
        <SettingsEntry icon="key" title="Anthropic API key"
                       :meta="[`Stored encrypted · changed ${fmtDateTime(state.api_key.updated_at)} · never shown again`, lastUsed]">
          <template #actions>
            <button type="button" class="btn-sm" data-test="test" :disabled="busy" @click="test"><Icon name="refresh" :size="14" />Test</button>
            <button type="button" class="btn-sm btn-delete" :disabled="busy" @click="remove"><Icon name="trash" :size="14" />Remove</button>
          </template>
        </SettingsEntry>
      </SettingsList>
    </SettingsSection>

    <SettingsSection v-if="state.api_key.set" title="Model">
      <div class="model-row">
        <select v-model="choice" name="model" aria-label="Claude model">
          <option value="">Latest Haiku (automatic) – currently {{ state.auto_model }}</option>
          <option v-for="m in models" :key="m.id" :value="m.id">{{ m.name }} ({{ m.id }})</option>
        </select>
        <button type="button" class="btn-sm" :disabled="busy" @click="saveModel"><Icon name="check" :size="14" />Use model</button>
        <button type="button" class="btn-sm" title="Ask Anthropic for the current model list" @click="refreshModels"><Icon name="refresh" :size="14" />Refresh list</button>
      </div>
      <span class="subtext">{{ models.length ? `${models.length} models available to this key, newest first.` : 'Model list not loaded yet.' }}
        Automatic picks the newest Haiku as soon as Anthropic offers it.</span>
    </SettingsSection>

    <form class="settings-form" @submit.prevent="save">
      <SecretField v-model="key" name="api_key" :label="state.api_key.set ? 'Replace API key' : 'Anthropic API key'"
                   :set="state.api_key.set" :updated-at="state.api_key.updated_at" placeholder="sk-ant-api03-…" required
                   :state="!state.api_key.set" />
      <div class="actions">
        <button type="submit" class="primary" :disabled="busy || !key.trim()"><Icon name="check" :size="15" />Save key</button>
      </div>
      <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
    </form>
  </SettingsCard>
</template>

<style scoped>
.model-row { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
.model-row select { flex: 1; min-width: 240px; }
</style>
