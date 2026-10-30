<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { fmtDateTime, timeAgo } from '../time.js'
import { useLive } from '../live.js'
import Icon from './Icon.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import SettingsSection from './SettingsSection.vue'

const state = ref({ current_version: null, built: null, public_key: null, last_check: null })
const message = ref(null)
const busy = ref(false)

async function load() {
  state.value = await api.get('/api/settings/releases')
}

async function checkNow() {
  busy.value = true
  message.value = null
  try {
    const r = await api.post('/api/settings/releases/sync')
    message.value = r.ok ? { kind: 'ok', text: `Checked. Active agent release: ${r.version ? `v${r.version}` : 'none yet'}` } : null
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

onMounted(load)
useLive(['settings'], load)

// Gesamtzustand für Kopf und Statusfeld
const health = computed(() => {
  const c = state.value.last_check
  if (!c) return { tone: 'neutral', text: 'Not checked yet' }
  return c.ok ? { tone: 'ok', text: `v${c.version ?? state.value.current_version}` } : { tone: 'danger', text: 'Action needed' }
})
</script>

<template>
  <SettingsCard icon="package" title="Agent Releases &amp; Updates" subtitle="Agents built and signed by this install from agent/ in the repository" :status="health">
    <template #intro>
      Every <code>docker compose up -d --build</code> rebuilds the agent when its code changed and signs it with this
      install's own key. The master verifies the signature, then offers the new version under Systems, where one passkey
      touch updates all hosts.
    </template>

    <SettingsSection title="Status">
      <SettingsList>
        <SettingsEntry icon="package" :title="state.current_version ? `v${state.current_version}` : 'No release yet'" mono
                       :meta="state.current_version ? `Active release, offered to the agents${state.built ? ` · built ${fmtDateTime(state.built)}` : ''}` : 'Built when the stack starts'" />
        <SettingsEntry icon="refresh" title="Release check"
                       :meta="state.last_check ? `${timeAgo(state.last_check.at)} · checks every minute` : 'not yet'">
          <template #badge>
            <span v-if="state.last_check" :class="['badge', state.last_check.ok ? 'ok' : 'danger']">{{ state.last_check.ok ? 'OK' : 'Failed' }}</span>
          </template>
          <template #actions>
            <button type="button" class="btn-sm" :disabled="busy" @click="checkNow"><Icon name="refresh" :size="14" />Check now</button>
          </template>
          <p v-if="state.last_check && !state.last_check.ok" class="message error" role="alert">
            <strong>{{ state.last_check.error }}</strong><template v-if="state.last_check.hint"><br />{{ state.last_check.hint }}</template>
          </p>
        </SettingsEntry>
        <SettingsEntry v-if="state.public_key" icon="key" title="Signing key" :meta="state.public_key">
          <template #badge><span class="badge neutral">Ed25519</span></template>
        </SettingsEntry>
      </SettingsList>
      <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
    </SettingsSection>
  </SettingsCard>
</template>
