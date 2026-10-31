<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import { useLive } from '../live.js'
import Icon from './Icon.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import ToggleSwitch from './ToggleSwitch.vue'

// Sofort-Alarm, wenn die offenen Funde eines Hosts in einem Lauf stark fallen (übernommener Worker, geschönte SBOM)
const form = reactive({ enabled: true, percent: 50, min_findings: 20 })
const message = ref(null)
const busy = ref(false)

async function load() {
  if (busy.value) return
  Object.assign(form, await api.get('/api/settings/finding-drop'))
}

async function save() {
  busy.value = true
  message.value = null
  try {
    await api.put('/api/settings/finding-drop', { enabled: form.enabled, percent: Number(form.percent), min_findings: Number(form.min_findings) })
    message.value = { kind: 'ok', text: 'Saved. Applies from the next scan run.' }
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

const status = computed(() => (form.enabled ? { tone: 'ok', text: 'Drop alarm on' } : { tone: 'warning', text: 'Drop alarm off', target: 'set-drop' }))
onMounted(load)
useLive(['settings'], load, 3000)
</script>

<template>
  <SettingsCard icon="shield" title="Alert rules" subtitle="Immediate alerts beyond new critical and high findings" :status="status">
    <form class="settings-form" @submit.prevent="save">
      <SettingsList label="Alert rules">
        <SettingsEntry id="set-drop" icon="shield" title="Sharp drop in findings"
                       :meta="form.enabled ? `Alerts when a host's open findings fall by ${form.percent} % or more in one run` : 'Off'">
          <template #actions>
            <ToggleSwitch v-model="form.enabled" name="drop_enabled" label="Alert on a sharp drop in findings" />
          </template>
          <div class="grid drop-fields">
            <label><span class="field-label">Alert at a drop of (%)</span>
              <input v-model.number="form.percent" name="drop_percent" type="number" min="10" max="100" :disabled="!form.enabled" required /></label>
            <label><span class="field-label">Only for hosts with at least … open findings</span>
              <input v-model.number="form.min_findings" name="drop_min" type="number" min="1" :disabled="!form.enabled" required /></label>
          </div>
          <span class="subtext">Catches a compromised worker or a doctored SBOM that reports a host as clean. A large update can trigger it too; the alert says what to check.</span>
        </SettingsEntry>
        <SettingsEntry icon="sparkles" title="Early warning fails" meta="Set with the AI early warning sources">
          <template #actions>
            <RouterLink to="/einstellungen?tab=ai#set-ai-sources" class="btn-link btn-sm">Open<Icon name="chevron" :size="14" /></RouterLink>
          </template>
        </SettingsEntry>
      </SettingsList>
      <div class="actions">
        <button class="primary" :disabled="busy"><Icon name="check" :size="15" />{{ busy ? 'Saving…' : 'Save alert rules' }}</button>
      </div>
      <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
    </form>
  </SettingsCard>
</template>

<style scoped>
.drop-fields { max-width: 40rem; }
</style>
