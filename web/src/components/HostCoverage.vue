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
</script>

<template>
  <section>
    <h3>Coverage</h3>
    <p v-if="error" class="text-danger">{{ error }}</p>
    <template v-else-if="row?.checks">
      <p class="subtext">
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

      <p v-if="row.last_scan">
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
h3 { margin-top: 1.2rem; }
.label { color: var(--muted); margin-right: 0.4rem; }
.detail-table th { text-transform: none; letter-spacing: 0; font-size: 0.85rem; color: var(--text); white-space: nowrap; vertical-align: top; }
.problem { margin: 0.5rem 0 0.8rem; }
.detail-table td { vertical-align: top; }
.fix-cmd { display: flex; align-items: center; gap: 0.35rem; max-width: 100%; margin-top: 0.45rem; padding: 0.3rem 0.35rem 0.3rem 0.6rem; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--ground); }
.fix-cmd code { flex: 1; min-width: 0; overflow-x: auto; white-space: nowrap; font-size: 0.76rem; color: var(--text); }
.fix-cmd .btn-sm { flex: none; }
/* Schmal: Prüfung und Status in einer Zeile, die Begründung darunter über die volle Breite */
@media (max-width: 640px) {
  .detail-table tr { display: grid; grid-template-columns: auto 1fr; gap: 0.4rem 0.75rem; align-items: center; padding: 0.7rem 0; border-bottom: 1px solid var(--line); }
  .detail-table tbody tr:last-child { border-bottom: none; }
  .detail-table th, .detail-table td { display: block; padding: 0; border: none; }
  .detail-table td:last-child { grid-column: 1 / -1; }
}
</style>
