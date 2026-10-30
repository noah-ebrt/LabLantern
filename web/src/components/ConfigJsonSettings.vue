<script setup>
import { computed, ref } from 'vue'
import { api } from '../api.js'
import Icon from './Icon.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsSection from './SettingsSection.vue'

// Die ganze Konfiguration als ein JSON-Dokument. Der Server schreibt jeden geänderten Abschnitt über dieselben
// Endpunkte wie die Formulare; Geheimnisse stehen als null darin (= unverändert) und kommen nie heraus.
const text = ref('')
const loaded = ref(false)
const results = ref(null)
const message = ref(null)
const busy = ref(false)

async function load() {
  text.value = JSON.stringify(await api.get('/api/settings/config'), null, 2)
  loaded.value = true
  results.value = null
}

const parseError = computed(() => {
  if (!loaded.value) return ''
  try {
    const v = JSON.parse(text.value)
    return v && typeof v === 'object' && !Array.isArray(v) ? '' : 'The document must be a JSON object'
  } catch (e) {
    return e.message
  }
})

async function save() {
  busy.value = true
  message.value = null
  try {
    const r = await api.put('/api/settings/config', JSON.parse(text.value))
    results.value = r.results
    message.value = r.ok ? { kind: 'ok', text: 'Saved. Changed sections were written, the rest left as they were.' }
      : { kind: 'error', text: 'Some sections were not saved, see below. The others were.' }
    if (r.ok) text.value = JSON.stringify(r.config, null, 2)
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

function download() {
  const url = URL.createObjectURL(new Blob([text.value], { type: 'application/json' }))
  const a = Object.assign(document.createElement('a'), { href: url, download: 'vulnwatch-config.json' })
  a.click()
  URL.revokeObjectURL(url)
}

const changed = computed(() => Object.entries(results.value || {}).filter(([, v]) => v !== 'unchanged'))
</script>

<template>
  <SettingsCard icon="settings" title="Configuration as JSON" subtitle="Every setting in one document: edit, copy to another install, or script it via PUT /api/settings/config">
    <SettingsSection title="Document">
      <div v-if="!loaded" class="actions start">
        <button type="button" class="btn-sm" @click="load"><Icon name="download" :size="14" />Load current configuration</button>
      </div>
      <template v-else>
        <textarea v-model="text" class="json" rows="24" spellcheck="false" aria-label="Configuration as JSON" />
        <p v-if="parseError" class="message error">{{ parseError }}</p>
        <p class="subtext">Secrets (API keys, tokens, passwords, channel URLs) show as <code>null</code>, which keeps them. Put a
          text in to replace one. Lists are complete: a channel or device missing from <code>notifications</code> or
          <code>appliances</code> is removed. Users, passkeys and agent tokens are not part of the document.</p>
        <div class="actions">
          <button type="button" class="btn-sm" :disabled="busy" @click="load"><Icon name="refresh" :size="14" />Reload</button>
          <button type="button" class="btn-sm" :disabled="!!parseError" @click="download"><Icon name="download" :size="14" />Download</button>
          <button type="button" class="primary" :disabled="busy || !!parseError" @click="save"><Icon name="check" :size="15" />{{ busy ? 'Saving…' : 'Save changes' }}</button>
        </div>
        <ul v-if="changed.length" class="results">
          <li v-for="[k, v] in changed" :key="k"><span class="mono">{{ k }}</span>
            <span :class="v.startsWith('error') ? 'text-danger' : 'text-success'">{{ v }}</span></li>
        </ul>
      </template>
    </SettingsSection>
    <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
  </SettingsCard>
</template>

<style scoped>
.json { width: 100%; resize: vertical; font-family: var(--mono); font-size: 0.78rem; line-height: 1.5; tab-size: 2; }
.actions.start { justify-content: flex-start; }
.results { list-style: none; margin: 0.5rem 0 0; padding: 0; font-size: 0.8rem; }
.results li { display: flex; gap: 0.6rem; padding: 0.15rem 0; overflow-wrap: anywhere; }
</style>
