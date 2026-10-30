<script setup>
import { onMounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import { clock, fmtDateTime } from '../time.js'
import Icon from './Icon.vue'
import ToggleSwitch from './ToggleSwitch.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import SettingsSection from './SettingsSection.vue'

const form = reactive({ enabled: true, time: '03:00', timezone: 'UTC' })
const savedTz = ref('UTC')
const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone
const zones = ['UTC', ...(Intl.supportedValuesOf?.('timeZone') || [browserTz]).filter((z) => z !== 'UTC')]
const nextRun = ref(null)
const message = ref(null)
const saving = ref(false)
// Kurzlauf: scannt zwischen den täglichen Läufen mit vorhandenen Agentendaten, meldet nur Neues
const short = reactive({ enabled: true, hours: 12, choices: [2, 3, 4, 6, 8, 12], agent_report_minutes: 55 })

async function load() {
  const s = await api.get('/api/settings/schedule')
  form.enabled = s.enabled
  form.time = s.time
  form.timezone = savedTz.value = s.timezone || 'UTC'
  clock.timeZone = savedTz.value
  nextRun.value = s.next_run
  Object.assign(short, await api.get('/api/settings/short-schedule').catch(() => ({})))
}

async function save() {
  saving.value = true
  message.value = null
  try {
    if (form.timezone !== savedTz.value) await api.put('/api/settings/timezone', { timezone: form.timezone })
    await api.put('/api/settings/schedule', { enabled: form.enabled, time: form.time })
    await api.put('/api/settings/short-schedule', { enabled: short.enabled, hours: Number(short.hours) })
    await load()
    message.value = { kind: 'ok', text: 'Schedule settings saved successfully.' }
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
  <SettingsCard icon="clock" title="Daily Vulnerability Scan" subtitle="Automatically inspect all registered Linux systems and containers every day"
                :status="form.enabled ? { tone: 'ok', text: 'Active' } : { tone: 'neutral', text: 'Disabled' }">
    <form class="settings-form" @submit.prevent="save">
      <SettingsSection title="Automatic runs">
        <SettingsList>
          <SettingsEntry icon="runs" title="Daily full run"
                         :meta="form.enabled ? `Every day at ${form.time} (${form.timezone}) · next ${nextRun ? fmtDateTime(nextRun) : 'calculating…'}`
                           : 'Off – scans only run when started by hand or by the short run'">
            <template #actions>
              <ToggleSwitch v-model="form.enabled" name="enabled" label="Daily full run" />
            </template>
            <label v-if="form.enabled" class="time-field">
              <span class="field-label">Time ({{ form.timezone }}, 24 h)</span>
              <input v-model="form.time" name="time" pattern="([01][0-9]|2[0-3]):[0-5][0-9]" required class="mono time-input" placeholder="03:00" />
            </label>
            <span class="subtext">Asks every agent for fresh data, scans, checks versions and AI early warnings, then sends the report.</span>
          </SettingsEntry>
          <SettingsEntry icon="refresh" title="Short run"
                         :meta="short.enabled ? `Every ${short.hours} h, aligned to the daily run` : 'Off'">
            <template #actions>
              <select v-model.number="short.hours" name="short_hours" :disabled="!short.enabled" aria-label="Short run interval" class="interval">
                <option v-for="h in short.choices" :key="h" :value="h">every {{ h }} h</option>
              </select>
              <ToggleSwitch v-model="short.enabled" name="short_enabled" label="Short run" />
            </template>
            <span class="subtext">Scans the latest agent data against a fresh database between daily runs and only notifies when something new is critical or high, or a check fails.</span>
            <span class="subtext">Agents report on their own about every {{ short.agent_report_minutes }} minutes, so a short run scans data at most about that old. They stay connected for commands, so a full run gets fresh data within seconds.</span>
          </SettingsEntry>
        </SettingsList>
      </SettingsSection>

      <label class="tz-field">
        <span class="field-label">System time zone</span>
        <select v-model="form.timezone" name="timezone" class="tz-select">
          <option v-for="z in zones" :key="z" :value="z">{{ z }}</option>
        </select>
        <span class="subtext">
          The daily run and every time in the interface use this zone.
          <button v-if="browserTz && form.timezone !== browserTz" type="button" class="link" @click="form.timezone = browserTz">Use {{ browserTz }}</button>
        </span>
      </label>

      <div class="actions">
        <button type="submit" class="primary" :disabled="saving"><Icon name="check" :size="15" />{{ saving ? 'Saving…' : 'Save schedule' }}</button>
      </div>
      <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
    </form>
  </SettingsCard>
</template>

<style scoped>
.time-field { max-width: 14rem; }
.time-input { width: 7rem; }
.interval { width: auto; min-height: 30px; padding-top: 0.2rem; padding-bottom: 0.2rem; font-size: 0.82rem; }
.tz-field { max-width: 26rem; }
</style>
