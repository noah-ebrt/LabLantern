<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import { timeAgo } from '../time.js'
import { useLive } from '../live.js'
import Icon from './Icon.vue'
import SecretField from './SecretField.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import SettingsSection from './SettingsSection.vue'

// Offsite-Wächter (optional): ein Dienst außer Haus schlägt Alarm, wenn vulnwatch verstummt.
// Healthchecks, Uptime Kuma oder ein eigener Dienst; der Herzschlag-Abstand ist einstellbar.
const PROVIDERS = [
  ['healthchecks', 'Healthchecks'],
  ['uptimekuma', 'Uptime Kuma'],
  ['custom', 'Custom URL'],
]
const PLACEHOLDER = {
  healthchecks: 'https://watch.example.org/ping/<uuid>',
  uptimekuma: 'https://kuma.example.org/api/push/<token>',
  custom: 'https://monitor.example.org/<path>',
}
const state = ref(null)
const form = reactive({ heartbeat_url: '', run_url: '', short_url: '' })
const config = reactive({ provider: 'healthchecks', heartbeat_minutes: 5 })
const editing = reactive({})
const open = ref(false)
const message = ref(null)
const busy = ref(false)
const schedule = ref({ enabled: true, time: '03:00', timezone: 'UTC' })
const short = ref({ enabled: true, hours: 12, hours_of_day: [15] })

async function load() {
  const [w, sch, sh] = await Promise.all([api.get('/api/settings/watchdog'), api.get('/api/settings/schedule').catch(() => null),
    api.get('/api/settings/short-schedule').catch(() => null)])
  state.value = w
  if (w.config) Object.assign(config, w.config)
  if (sch) schedule.value = sch
  if (sh) short.value = sh
}

const anySet = computed(() => ['heartbeat', 'run', 'short'].some((k) => state.value?.[k]?.set))
const daily = computed(() => (schedule.value.time || '03:00').split(':').map(Number))

// Was im fremden Dienst einzustellen ist, je Anbieter und Prüfung
function setup(key) {
  const m = config.heartbeat_minutes
  const [h, min] = daily.value
  const tz = schedule.value.timezone || 'UTC'
  const p = config.provider
  if (key === 'heartbeat') {
    return p === 'healthchecks' ? `Simple · period ${m} min · grace ${m * 2} min`
      : p === 'uptimekuma' ? `Push monitor · heartbeat interval ${m * 60} s · retries 1` : `expects a POST every ${m} min`
  }
  if (key === 'run') {
    if (!schedule.value.enabled) return 'daily run is switched off in the schedule'
    return p === 'healthchecks' ? `Cron ${min} ${h} * * * · time zone ${tz} · grace 2 h`
      : p === 'uptimekuma' ? 'Push monitor · heartbeat interval 90000 s (25 h)' : `expects a POST once a day after ${schedule.value.time} ${tz}`
  }
  if (!short.value.enabled) return 'short run is switched off in the schedule'
  return p === 'healthchecks' ? `Cron ${min} ${(short.value.hours_of_day || []).join(',')} * * * · time zone ${tz} · grace 1 h`
    : p === 'uptimekuma' ? `Push monitor · heartbeat interval ${(short.value.hours + 1) * 3600} s (${short.value.hours + 1} h)` : `expects a POST every ${short.value.hours} h`
}
const CHECKS = computed(() => [
  { key: 'heartbeat', field: 'heartbeat_url', title: 'Heartbeat', icon: 'activity', what: `every ${config.heartbeat_minutes} min while master and worker are alive` },
  { key: 'run', field: 'run_url', title: 'Daily run', icon: 'runs', what: 'result of every daily run' },
  { key: 'short', field: 'short_url', title: 'Short run', icon: 'refresh', what: 'optional · the runs between daily runs' },
])
const failing = (k) => state.value?.[k]?.set && state.value[k].last && !state.value[k].last.ok
const showField = (c) => editing[c.key] || (!state.value?.[c.key]?.set && open.value)

async function save() {
  busy.value = true
  message.value = null
  try {
    await api.put('/api/settings/watchdog', { ...config, heartbeat_url: form.heartbeat_url || null, run_url: form.run_url || null,
      short_url: form.short_url || null })
    Object.assign(form, { heartbeat_url: '', run_url: '', short_url: '' })
    for (const k of Object.keys(editing)) delete editing[k]
    await load()
    if (!anySet.value) {
      message.value = { kind: 'ok', text: 'Saved.' }
      return
    }
    const r = await api.post('/api/settings/watchdog/test')
    const bad = Object.entries(r).filter(([, v]) => !v.ok)
    message.value = bad.length
      ? { kind: 'error', text: `Saved, but the test ping failed: ${bad.map(([k, v]) => `${k}: ${v.error}`).join('; ')}` }
      : { kind: 'ok', text: 'Saved. Test ping delivered.' }
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

async function remove(kind) {
  if (!confirm('Remove this ping URL? vulnwatch then stops pinging this check, and the monitor will alert once it is overdue.')) return
  await api.put('/api/settings/watchdog', { clear: [kind] })
  await load()
}

const health = computed(() => {
  const s = state.value
  if (!s) return null
  if (!anySet.value) return { tone: 'neutral', text: 'Not set up' }
  const broken = ['heartbeat', 'run', 'short'].find(failing)
  if (broken) return { tone: 'danger', text: 'Ping failing', target: `set-wd-${broken}` }
  const missing = ['heartbeat', 'run'].find((k) => !s[k]?.set)
  return missing ? { tone: 'warning', text: 'Partly set up', target: `set-wd-${missing}` } : { tone: 'ok', text: 'Active' }
})

onMounted(load)
useLive(['settings'], load)
</script>

<template>
  <SettingsCard icon="activity" title="Offsite watchdog" subtitle="A monitor outside your network alerts you when vulnwatch itself goes quiet" :status="health">
    <template v-if="state">
      <SettingsList v-if="!anySet && !open" empty empty-text="Not set up. Works with Healthchecks, Uptime Kuma or any URL that alerts when pings stop.">
        <template #empty>
          <button type="button" class="btn-sm" @click="open = true"><Icon name="plus" :size="14" />Set up</button>
        </template>
      </SettingsList>

      <form v-else class="settings-form" @submit.prevent="save">
        <div class="controls">
          <div class="seg" role="radiogroup" aria-label="Monitoring service">
            <button v-for="[v, l] in PROVIDERS" :key="v" type="button" role="radio" :aria-checked="config.provider === v"
                    :class="['seg-btn', { active: config.provider === v }]" @click="config.provider = v">{{ l }}</button>
          </div>
          <label class="interval">
            <span class="field-label">Ping every</span>
            <select v-model.number="config.heartbeat_minutes" name="heartbeat_minutes">
              <option v-for="m in state.heartbeat_choices" :key="m" :value="m">{{ m }} min</option>
            </select>
          </label>
        </div>
        <p class="subtext">
          <template v-if="config.provider === 'healthchecks'">vulnwatch pings start, success and failure with the reason.</template>
          <template v-else-if="config.provider === 'uptimekuma'">Create push monitors; vulnwatch sends status up or down with a message.</template>
          <template v-else>vulnwatch sends a POST on success only; your monitor alerts when it stops arriving.</template>
        </p>

        <SettingsSection title="Checks" :count="CHECKS.filter((c) => state[c.key]?.set).length">
          <SettingsList>
            <SettingsEntry v-for="c in CHECKS" :id="`set-wd-${c.key}`" :key="c.key" :icon="c.icon" :title="c.title"
                           :meta="[c.what, `Monitor: ${setup(c.key)}`]">
              <template #badge>
                <span :class="['badge', !state[c.key].set ? 'neutral' : failing(c.key) ? 'danger' : 'ok']">
                  {{ !state[c.key].set ? 'Not set' : failing(c.key) ? 'Failing' : 'Configured' }}
                </span>
              </template>
              <template v-if="state[c.key].set" #meta>
                <span class="entry-line"><span class="mono">{{ state[c.key].target }}</span>
                  <template v-if="state[c.key].last"> · last ping {{ timeAgo(state[c.key].last.at) }}{{ state[c.key].last.error ? ` – ${state[c.key].last.error}` : '' }}</template>
                </span>
              </template>
              <template #actions>
                <button v-if="state[c.key].set" type="button" class="btn-sm" @click="editing[c.key] = !editing[c.key]">{{ editing[c.key] ? 'Cancel' : 'Change URL' }}</button>
                <button v-else-if="!open" type="button" class="btn-sm" @click="editing[c.key] = true">Set URL</button>
                <button v-if="state[c.key].set" type="button" class="btn-sm btn-delete" @click="remove(c.key)"><Icon name="trash" :size="14" />Remove</button>
              </template>
              <SecretField v-if="showField(c)" v-model="form[c.field]" :name="c.field" :label="state[c.key].set ? 'New ping URL' : 'Ping URL'"
                           :set="!!state[c.key].set" :placeholder="PLACEHOLDER[config.provider]" :state="false" />
            </SettingsEntry>
          </SettingsList>
        </SettingsSection>

        <div class="actions">
          <button type="submit" class="primary" :disabled="busy"><Icon name="check" :size="15" />{{ busy ? 'Saving & testing…' : 'Save and send test ping' }}</button>
          <button v-if="!anySet" type="button" class="secondary" @click="open = false">Cancel</button>
        </div>
      </form>
      <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
    </template>
  </SettingsCard>
</template>

<style scoped>
.controls { display: flex; align-items: flex-end; justify-content: space-between; gap: 0.75rem 1.25rem; flex-wrap: wrap; }
.interval { flex-direction: row; align-items: center; gap: 0.5rem; }
.interval select { width: auto; }
.entry-line { font-size: 0.8125rem; color: var(--muted); overflow-wrap: anywhere; }
.entry-line .mono { font-size: 0.75rem; color: var(--text-2); }
</style>
