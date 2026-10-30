<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { APPLIANCE_KINDS } from '../labels.js'
import { fmtDateTime, timeAgo } from '../time.js'
import EarlyWarningWatch from './EarlyWarningWatch.vue'
import HostCoverage from './HostCoverage.vue'
import Modal from './Modal.vue'

// Was ein Connector zuletzt gelesen hat (TrueNAS, Home Assistant), auch das, was keinen Fund ergibt
const props = defineProps({ systemId: { type: Number, required: true } })
const emit = defineEmits(['close'])

const system = ref(null)
const error = ref('')
onMounted(async () => {
  try {
    system.value = await api.get(`/api/systems/${props.systemId}`)
  } catch (e) {
    error.value = e.message
  }
})

const data = computed(() => system.value?.inventory?.connector || {})
const kind = computed(() => system.value?.host_type)
const readError = computed(() => system.value?.collection_errors?.connector)

// Backup-Sensoren: ältester vergangener Zeitstempel = letzter Erfolg, jüngster = letzter Versuch, Zukunft = nächster
const backup = computed(() => {
  const b = data.value.backup
  if (!b?.present) return null
  const now = Date.now()
  const times = (b.times || []).map((t) => new Date(t)).filter((d) => !isNaN(d))
  const past = times.filter((d) => d <= now).sort((a, b) => a - b)
  return { success: past[0] || null, attempt: past[past.length - 1] || null, next: times.find((d) => d > now) || null }
})
const updatesOpen = computed(() => (data.value.updates || []).filter((u) => u.state === 'on'))
// Batterien: niedrigste zuerst (gemeldete „low“ ganz oben), umkehrbar; erst fünf, dann alle
const batteryDesc = ref(false)
const showAllBatteries = ref(false)
const batteries = computed(() => {
  const rank = (b) => (b.low ? -1 : b.level ?? 101)
  const sorted = [...(data.value.batteries || [])].sort((a, b) => rank(a) - rank(b))
  return batteryDesc.value ? sorted.reverse() : sorted
})
const shownBatteries = computed(() => (showAllBatteries.value ? batteries.value : batteries.value.slice(0, 5)))
const appsBehind = computed(() => (data.value.apps || []).filter((a) => a.upgrade || a.image_updates))
const tone = (bad, warn) => (bad ? 'text-danger' : warn ? 'text-warning' : '')
const iso = (d) => d?.toISOString()
</script>

<template>
  <Modal size="lg" :label="system ? `Host ${system.name}` : 'Host'" @close="emit('close')">
    <p v-if="error" class="message error" role="alert">{{ error }}</p>
    <div v-else-if="!system" class="empty">Loading…</div>
    <div v-else>
      <h2>{{ system.name }}</h2>
      <p class="subtitle">{{ APPLIANCE_KINDS[kind] }} {{ data.version || '' }} · read via API
        <template v-if="system.last_seen"> · last read {{ timeAgo(system.last_seen) }}</template></p>
      <p v-if="readError" class="message error">Last read failed: {{ readError }}</p>
      <p class="subtext">Problems also appear as <RouterLink :to="{ path: '/funde', query: { source: 'appliances', q: system.name } }" @click="emit('close')">findings</RouterLink>.
        Read every 6 hours; Test in the host list reads now.</p>

      <HostCoverage :system-id="systemId" />

      <template v-if="kind === 'homeassistant'">
        <h3>State</h3>
        <table class="data-table kv">
          <tr><th>Run state</th><td :class="tone(data.recovery_mode || data.safe_mode)">{{ data.recovery_mode ? 'recovery mode' : data.safe_mode ? 'safe mode' : (data.state || '?').toLowerCase() }}</td></tr>
          <tr><th>Last successful backup</th>
            <td v-if="!backup" class="text-warning">no automatic backups configured</td>
            <td v-else-if="!backup.success" class="text-danger">never</td>
            <td v-else :title="fmtDateTime(iso(backup.success))">{{ timeAgo(iso(backup.success)) }}
              <span v-if="backup.attempt - backup.success > 3600e3" class="text-danger"> · last attempt {{ timeAgo(iso(backup.attempt)) }} failed</span></td></tr>
          <tr v-if="backup?.next"><th>Next automatic backup</th><td>{{ fmtDateTime(iso(backup.next)) }}</td></tr>
          <tr v-for="d in data.disks || []" :key="d.entity_id"><th>{{ d.name }}</th>
            <td :class="tone(d.percent >= 95, d.percent >= 90)">{{ d.percent.toFixed(0) }} % used</td></tr>
        </table>

        <h3>Updates ({{ updatesOpen.length }} open of {{ (data.updates || []).length }})</h3>
        <table v-if="updatesOpen.length" class="data-table">
          <thead><tr><th>Component</th><th>Installed</th><th>Available</th></tr></thead>
          <tbody><tr v-for="u in updatesOpen" :key="u.entity_id"><td>{{ u.name }}</td><td class="mono">{{ u.version }}</td><td class="mono">{{ u.latest }}</td></tr></tbody>
        </table>
        <p v-else class="subtext">Everything up to date.</p>

        <h3>Batteries ({{ batteries.length }})
          <button v-if="batteries.length > 1" type="button" class="link sort" @click="batteryDesc = !batteryDesc">{{ batteryDesc ? 'high to low' : 'low to high' }}</button></h3>
        <table v-if="batteries.length" class="data-table">
          <tbody><tr v-for="b in shownBatteries" :key="b.entity_id"><td>{{ b.name }}</td>
            <td :class="['mono', tone(b.low || (b.level ?? 100) < 15, (b.level ?? 100) < 30)]">{{ b.level == null ? (b.low ? 'low' : 'ok') : `${b.level.toFixed(0)} %` }}</td></tr></tbody>
        </table>
        <button v-if="batteries.length > 5" type="button" class="link" @click="showAllBatteries = !showAllBatteries">
          {{ showAllBatteries ? 'Show fewer' : `Show all ${batteries.length}` }}</button>
        <p v-else-if="!batteries.length" class="subtext">No battery entities.</p>
      </template>

      <template v-else>
        <h3>System</h3>
        <table class="data-table kv">
          <tr><th>Installed</th><td class="mono">{{ data.version || '?' }}</td></tr>
          <tr><th>Update</th><td :class="tone(false, data.new_version)">{{ data.new_version || 'none available' }}</td></tr>
          <tr><th>Reboot</th><td :class="tone(false, data.reboot_required)">{{ data.reboot_required ? 'required for the update' : 'not needed' }}</td></tr>
        </table>

        <h3>Alerts ({{ (data.alerts || []).length }})</h3>
        <table v-if="(data.alerts || []).length" class="data-table">
          <tbody><tr v-for="a in data.alerts" :key="a.uuid"><td class="mono">{{ a.level }}</td><td>{{ a.text }}</td></tr></tbody>
        </table>
        <p v-else class="subtext">No open alerts.</p>

        <h3>Apps ({{ (data.apps || []).length }}, {{ appsBehind.length }} with updates)</h3>
        <table v-if="(data.apps || []).length" class="data-table">
          <thead><tr><th>App</th><th>State</th><th>Installed</th><th>Update</th></tr></thead>
          <tbody><tr v-for="a in data.apps" :key="a.name"><td>{{ a.name }}</td><td>{{ a.state.toLowerCase() }}</td><td class="mono">{{ a.version }}</td>
            <td :class="tone(false, a.upgrade || a.image_updates)">{{ a.upgrade ? a.latest || 'newer version' : a.image_updates ? 'newer image' : '–' }}</td></tr></tbody>
        </table>
      </template>

      <EarlyWarningWatch :system-id="systemId" />
    </div>
  </Modal>
</template>

<style scoped>
h3 { margin-top: 1.2rem; }
.kv th { text-align: left; font-weight: 500; color: var(--muted); width: 14rem; }
.text-warning { color: var(--med); }
.sort { font-size: 0.75rem; font-weight: 400; margin-left: 0.5rem; }
</style>
