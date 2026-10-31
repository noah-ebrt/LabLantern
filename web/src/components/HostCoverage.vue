<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api.js'
import { CHECKS, checkClass, fmtNum as fmt, label } from '../labels.js'
import { useLive } from '../live.js'
import { ago, fmtDateTime } from '../time.js'
import Icon from './Icon.vue'

// Zeile der Abdeckungsmatrix in der Host-Ansicht: Prüfungen, letzter Scan und was nicht prüfbar war
const props = defineProps({ systemId: { type: Number, required: true } })

const STATUS_HELP = {
  ok: 'Checked, nothing to do.',
  fund: 'Checked, needs attention.',
  fehler: 'Could not be checked – see the reason.',
  offen: 'New data or a new host – checked in the next scan run.',
  na: 'The device API does not provide this check.',
  excluded: 'Excluded from coverage on purpose, see the reason above.',
}

// Ein mitgelieferter Befehl (z. B. Container neu erstellen) gehört in ein Kopierfeld, nicht in den Fließtext
// (wie die nächsten Schritte der Übersicht, actions.py)
const COMMAND = /:?\s*(cd \S+ && docker compose [^;]+)/
function split(check) {
  const detail = check?.detail || ''
  if (check?.command) return { text: detail, command: check.command }
  const m = detail.match(COMMAND)
  return m ? { text: detail.replace(m[0], '').trim(), command: m[1].trim() } : { text: detail, command: '' }
}
const copied = ref('')
async function copy(key, text) {
  try {
    await navigator.clipboard.writeText(text)
    copied.value = key
    setTimeout(() => { if (copied.value === key) copied.value = '' }, 1600)
  } catch { /* ohne Clipboard-Rechte bleibt der Befehl markierbar */ }
}

const row = ref(null)
const error = ref('')
async function load() {
  try {
    row.value = await api.get(`/api/systems/${props.systemId}/coverage`)
  } catch (e) {
    error.value = e.message
  }
}
onMounted(load)
useLive(['systems'], load)

// Ausnahme von der Abdeckung (z. B. gestoppte Test-VM): mit Grund und Datum, höchstens 180 Tage
const isoDay = (days) => new Date(Date.now() + days * 86400000).toISOString().slice(0, 10)
const excluding = ref(false)
const exclude = ref({ until: '', reason: '' })
const busy = ref(false)
function openExclude() {
  exclude.value = { until: isoDay(30), reason: '' }
  excluding.value = true
}
async function submitExclude() {
  busy.value = true
  error.value = ''
  try {
    await api.post('/api/coverage/exclusions', { subject: `system:${props.systemId}`, ...exclude.value })
    excluding.value = false
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}
async function includeAgain() {
  busy.value = true
  try {
    await api.del(`/api/coverage/exclusions/${row.value.excluded.id}`)
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section>
    <h3>Coverage</h3>
    <p v-if="error" class="text-danger">{{ error }}</p>
    <template v-else-if="row?.checks">
      <p v-if="row.excluded" class="notice" data-test="excluded">
        Excluded from coverage until {{ row.excluded.until.slice(0, 10) }}: {{ row.excluded.reason }}
        <button type="button" class="btn-sm" data-test="include" :disabled="busy" @click="includeAgain">Include again</button>
      </p>
      <template v-else>
        <button v-if="!excluding" type="button" class="btn-sm" data-test="exclude" @click="openExclude">Exclude from coverage…</button>
        <form v-else class="exclude" @submit.prevent="submitExclude">
          <label>Until (max. 180 days)
            <input v-model="exclude.until" type="date" name="exclude_until" required :min="isoDay(1)" :max="isoDay(180)" />
          </label>
          <label>Reason
            <input v-model="exclude.reason" name="exclude_reason" required minlength="3" maxlength="500" placeholder="e.g. stopped test VM" />
          </label>
          <span class="subtext">The host no longer counts against coverage and is shown as excluded with this reason. It counts again on that date.</span>
          <div class="actions">
            <button type="button" class="secondary btn-sm" @click="excluding = false">Cancel</button>
            <button type="submit" class="primary btn-sm" :disabled="busy">Exclude</button>
          </div>
        </form>
      </template>
      <p class="subtext report-age">
        {{ row.status === 'connector' ? 'Last read' : 'Last agent report' }} {{ ago(row.age_hours) }}
        <template v-if="row.status !== 'connector'"> ·
          <template v-if="row.last_scan">last scanned in run #{{ row.last_scan.run_id }} ({{ fmtDateTime(row.last_scan.at) }})</template>
          <template v-else>not scanned yet</template>
        </template>
      </p>
      <div class="table-wrap">
        <table class="data-table detail-table">
          <tbody>
            <tr v-for="[k, l] in CHECKS" :key="k">
              <th scope="row">{{ l }}</th>
              <td><span :class="checkClass(row.checks[k].status)">{{ label(row.checks[k].status) }}</span></td>
              <td>
                <span class="detail-text">{{ split(row.checks[k]).text }}</span>
                <span v-if="split(row.checks[k]).command" class="fix-cmd">
                  <code class="mono">{{ split(row.checks[k]).command }}</code>
                  <button class="btn-sm" :aria-label="`Copy command for ${l}`" @click="copy(k, split(row.checks[k]).command)">
                    <Icon :name="copied === k ? 'check' : 'copy'" :size="13" />{{ copied === k ? 'Copied' : 'Copy' }}
                  </button>
                </span>
                <span class="subtext">{{ split(row.checks[k]).command ? 'Run this on the host, then press Report now.' : STATUS_HELP[row.checks[k].status] }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p v-if="row.last_scan" class="status-line last-scan">
        <span class="label">Last scan:</span>
        <span :class="['badge', row.last_scan.status === 'ok' ? 'ok' : 'danger']">{{ row.last_scan.status === 'ok' ? 'OK' : 'FAILED' }}</span>
        {{ fmt(row.last_scan.findings_count) }} findings ·
        <RouterLink :to="{ path: '/laeufe', query: { run: row.last_scan.run_id } }">run #{{ row.last_scan.run_id }}</RouterLink>
      </p>
      <pre v-if="row.last_scan?.error" class="cmd">{{ row.last_scan.error }}</pre>

      <template v-if="row.image_problems?.length">
        <h4>Images that could not be checked ({{ row.image_problems.length }})</h4>
        <div v-for="p in row.image_problems" :key="p.image_id" class="problem">
          <span class="strong mono">{{ p.image }}</span>
          <pre class="cmd">{{ p.error }}</pre>
        </div>
      </template>

      <!-- Bei Connectors steht der Lesefehler schon oben in der Ansicht -->
      <template v-if="row.status !== 'connector' && Object.keys(row.collection_errors || {}).length">
        <h4>What the agent could not collect</h4>
        <div v-for="(msg, key) in row.collection_errors" :key="key" class="problem">
          <span class="strong">{{ key }}</span>
          <pre class="cmd">{{ msg }}</pre>
        </div>
      </template>
    </template>
  </section>
</template>

<style scoped>
.exclude { display: grid; gap: 0.5rem; max-width: 26rem; margin: 0.5rem 0 0.75rem; }
.exclude .actions { display: flex; gap: 0.5rem; }
h3 { margin-top: 1.25rem; }
.label { color: var(--muted); }
.report-age { margin-top: 0.5rem; }
.last-scan { margin-top: 1rem; }
.detail-table th { text-transform: none; letter-spacing: 0; font-size: 0.8125rem; color: var(--text); white-space: nowrap; vertical-align: top; }
.problem { margin: 0.5rem 0 0.75rem; }
.detail-table td { vertical-align: top; }
.fix-cmd { display: flex; align-items: center; gap: 0.25rem; max-width: 100%; margin-top: 0.5rem; padding: 0.25rem 0.25rem 0.25rem 0.5rem; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--ground); }
.fix-cmd code { flex: 1; min-width: 0; overflow-x: auto; white-space: nowrap; font-size: 0.75rem; color: var(--text); }
.fix-cmd .btn-sm { flex: none; }
/* Schmal: Prüfung und Status in einer Zeile, die Begründung darunter über die volle Breite */
@media (max-width: 640px) {
  .detail-table tr { display: grid; grid-template-columns: auto 1fr; gap: 0.5rem 0.75rem; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid var(--line); }
  .detail-table tbody tr:last-child { border-bottom: none; }
  .detail-table th, .detail-table td { display: block; padding: 0; border: none; }
  .detail-table td:last-child { grid-column: 1 / -1; }
}
</style>
