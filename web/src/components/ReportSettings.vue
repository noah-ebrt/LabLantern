<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import { fmtDayOnly } from '../time.js'
import Icon from './Icon.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'

// Bericht des täglichen Laufs: Alarme und Fehler gehen immer am selben Tag raus, egal was hier steht
const report = reactive({ frequency: 'daily', weekday: 0, paused_until: '' })
const weekdays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
const message = ref(null)
const saving = ref(false)

async function load() {
  const p = await api.get('/api/settings/report-policy').catch(() => ({}))
  Object.assign(report, { frequency: p.frequency || 'daily', weekday: p.weekday ?? 0, paused_until: p.paused_until || '' })
}

async function save() {
  saving.value = true
  message.value = null
  try {
    await api.put('/api/settings/report-policy', { frequency: report.frequency, weekday: Number(report.weekday),
                                                   paused_until: report.paused_until || null })
    message.value = { kind: 'ok', text: 'Report settings saved.' }
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    saving.value = false
  }
}

const cadence = computed(() => (report.frequency === 'weekly' ? `Weekly on ${weekdays[report.weekday]}`
  : report.frequency === 'on_change' ? 'Only on change' : 'Daily'))
const status = computed(() => (report.paused_until ? { tone: 'warning', text: `Paused until ${fmtDayOnly(report.paused_until)}`, target: 'set-pause' }
  : { tone: 'neutral', text: cadence.value }))

onMounted(load)
</script>

<template>
  <SettingsCard icon="mail" title="Scan report" subtitle="The summary after each daily run. Alerts and errors always go out right away." :status="status">
    <form class="settings-form" @submit.prevent="save">
      <SettingsList label="Report">
        <SettingsEntry id="set-report" icon="mail" title="How often" meta="On days when everything is OK or only warnings are open">
          <template #actions>
            <select v-model="report.frequency" name="report_frequency" aria-label="Report frequency" class="interval">
              <option value="daily">daily</option>
              <option value="weekly">weekly</option>
              <option value="on_change">only on change</option>
            </select>
            <select v-if="report.frequency === 'weekly'" v-model.number="report.weekday" name="report_weekday" aria-label="Weekday" class="interval">
              <option v-for="(d, i) in weekdays" :key="d" :value="i">{{ d }}</option>
            </select>
          </template>
          <span class="subtext">“Only on change” sends it when findings are new, resolved, reopened or changed, or a host could not be checked.
            Runs started by hand always report.</span>
        </SettingsEntry>
        <SettingsEntry id="set-pause" icon="clock" title="Pause"
                       :meta="report.paused_until ? `No report until ${fmtDayOnly(report.paused_until)}; alerts still go out` : 'For a vacation or a rebuild; alerts still go out'">
          <template #actions>
            <input v-model="report.paused_until" type="date" name="paused_until" class="mono interval" aria-label="Pause the report until" />
            <button v-if="report.paused_until" type="button" class="btn-sm" @click="report.paused_until = ''"><Icon name="x" :size="14" />Clear</button>
          </template>
        </SettingsEntry>
      </SettingsList>

      <div class="actions">
        <button type="submit" class="primary" :disabled="saving"><Icon name="check" :size="15" />{{ saving ? 'Saving…' : 'Save report settings' }}</button>
      </div>
      <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
    </form>
  </SettingsCard>
</template>

<style scoped>
.interval { width: auto; min-height: 30px; padding-top: 0.2rem; padding-bottom: 0.2rem; font-size: 0.82rem; }
</style>
