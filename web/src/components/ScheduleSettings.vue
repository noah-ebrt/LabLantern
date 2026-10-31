<script setup>
import { onMounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import { clock, fmtWeekdayTime } from '../time.js'
import Icon from './Icon.vue'
import ToggleSwitch from './ToggleSwitch.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'

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
    message.value = { kind: 'ok', text: 'Schedule saved.' }
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
  <SettingsCard icon="clock" title="Scan schedule" subtitle="When vulnwatch scans every host and container on its own"
                :status="form.enabled ? { tone: 'ok', text: 'Active' } : { tone: 'neutral', text: 'Disabled', target: 'set-daily' }">
    <form class="settings-form" @submit.prevent="save">
      <SettingsList label="Automatic runs">
        <SettingsEntry id="set-daily" icon="runs" title="Daily full run"
                       :meta="form.enabled ? `Every day at ${form.time} · next ${nextRun ? fmtWeekdayTime(nextRun) : 'calculating…'}`
                         : 'Off: scans only run when started by hand or by the short run'">
          <template #actions>
            <input v-if="form.enabled" v-model="form.time" name="time" pattern="([01][0-9]|2[0-3]):[0-5][0-9]" required
                   class="mono time-input" placeholder="03:00" aria-label="Time of the daily run (24 h)" />
            <ToggleSwitch v-model="form.enabled" name="enabled" label="Daily full run" />
          </template>
          <span class="subtext">Asks every agent for fresh data, scans it, checks image versions and runs the AI early warning, then sends the report.</span>
        </SettingsEntry>
        <SettingsEntry id="set-short" icon="refresh" title="Short run"
                       :meta="short.enabled ? `Every ${short.hours} h between the daily runs` : 'Off'">
          <template #actions>
            <select v-model.number="short.hours" name="short_hours" :disabled="!short.enabled" aria-label="Short run interval" class="interval">
              <option v-for="h in short.choices" :key="h" :value="h">every {{ h }} h</option>
            </select>
            <ToggleSwitch v-model="short.enabled" name="short_enabled" label="Short run" />
          </template>
          <span class="subtext">A quick rescan of the latest agent data (at most about {{ short.agent_report_minutes }} min old) against a fresh vulnerability database.
            It only notifies about new critical or high findings and failed checks.</span>
        </SettingsEntry>
        <SettingsEntry id="set-timezone" icon="clock" title="Time zone" meta="For the daily run and every time shown in vulnwatch">
          <template #actions>
            <select v-model="form.timezone" name="timezone" class="interval tz-select" aria-label="System time zone">
              <option v-for="z in zones" :key="z" :value="z">{{ z }}</option>
            </select>
          </template>
          <span v-if="browserTz && form.timezone !== browserTz" class="subtext">
            This browser is in {{ browserTz }}. <button type="button" class="link" @click="form.timezone = browserTz">Use {{ browserTz }}</button>
          </span>
        </SettingsEntry>
      </SettingsList>

      <div class="actions">
        <button type="submit" class="primary" :disabled="saving"><Icon name="check" :size="15" />{{ saving ? 'Saving…' : 'Save schedule' }}</button>
      </div>
      <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
    </form>
  </SettingsCard>
</template>

<style scoped>
.time-input { width: 5.5rem; min-height: 30px; padding-top: 0.2rem; padding-bottom: 0.2rem; font-size: 0.82rem; text-align: center; }
.interval { width: auto; min-height: 30px; padding-top: 0.2rem; padding-bottom: 0.2rem; font-size: 0.82rem; }
.tz-select { max-width: 13rem; }
</style>
