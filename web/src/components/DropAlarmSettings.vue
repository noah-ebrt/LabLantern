<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import { useLive } from '../live.js'
import Icon from './Icon.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsSection from './SettingsSection.vue'
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

const status = computed(() => (form.enabled ? { tone: 'ok', text: `On · ${form.percent} %` } : { tone: 'warning', text: 'Off' }))
onMounted(load)
useLive(['settings'], load, 3000)
</script>

<template>
  <SettingsCard icon="shield" title="Sharp drop alarm" subtitle="Immediate alert when a host's open findings fall sharply in one run" :status="status">
    <SettingsSection title="Rule">
      <form class="settings-form" @submit.prevent="save">
        <ToggleSwitch v-model="form.enabled" name="drop_enabled" label="Alert on a sharp drop" />
        <div class="grid">
          <label><span class="field-label">Drop of at least (%)</span>
            <input v-model.number="form.percent" name="drop_percent" type="number" min="10" max="100" :disabled="!form.enabled" required /></label>
          <label><span class="field-label">Only from findings before</span>
            <input v-model.number="form.min_findings" name="drop_min" type="number" min="1" :disabled="!form.enabled" required /></label>
        </div>
        <p class="subtext">A compromised worker or an agent with a doctored SBOM can report a host as clean. This catches it: from
          {{ form.min_findings }} open scanner findings on, a fall of {{ form.percent }} % or more in one run sends an immediate alert.
          A large update can trigger it too; the alert says what to check.</p>
        <div class="actions">
          <button class="primary" :disabled="busy"><Icon name="check" :size="15" />{{ busy ? 'Saving…' : 'Save' }}</button>
        </div>
      </form>
    </SettingsSection>
    <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
  </SettingsCard>
</template>
