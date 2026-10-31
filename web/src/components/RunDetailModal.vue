<script setup>
import { onMounted, ref } from 'vue'
import { api } from '../api.js'
import { RUN_ACTIVE, fmtNum, label, runLabel } from '../labels.js'
import { fmtDateTime, parseTime } from '../time.js'
import { useLive } from '../live.js'
import RunProgress from './RunProgress.vue'
import Modal from './Modal.vue'

// Ergebnis eines Laufs mit allen Hosts; genutzt von Scan-Läufe und Übersicht
const props = defineProps({ runId: { type: Number, required: true } })
const emit = defineEmits(['close'])

const run = ref(null)
const error = ref('')

const fmtTime = (iso) => fmtDateTime(iso) || '–'
const duration = (r) => {
  if (!r.finished_at) return 'still running'
  const s = Math.round((parseTime(r.finished_at) - parseTime(r.started_at)) / 1000)
  return s < 120 ? `${s} s` : `${Math.round(s / 60)} min`
}

async function load() {
  try {
    run.value = await api.get(`/api/runs/${props.runId}`)
  } catch (e) {
    error.value = e.message
  }
}
onMounted(load)
// Läuft der Lauf noch, zeigt der Dialog den Live-Fortschritt und lädt beim Abschluss das Ergebnis
useLive(['runs'], load, 500)
</script>

<template>
  <Modal size="lg" :label="`Run ${runId}`" @close="emit('close')">
    <p v-if="error" class="message error" role="alert">{{ error }}</p>
    <div v-else-if="!run" class="empty">Loading run…</div>
    <template v-else>
      <h2>Run #{{ run.id }}</h2>
      <p class="subtitle">{{ run.trigger === 'manual' ? 'Started manually' : 'Scheduled' }} · {{ fmtTime(run.started_at) }} · {{ duration(run) }}</p>
      <RunProgress v-if="RUN_ACTIVE.includes(run.status)" class="live" @done="load" />
      <dl class="facts-grid">
        <div><dt>Status</dt><dd>{{ runLabel(run.status) }}</dd></div>
        <div><dt>Canary test</dt><dd>{{ run.canary_details || run.canary_status }}</dd></div>
        <div><dt>Vulnerability database</dt><dd>{{ run.db_status?.built ? `built ${fmtTime(run.db_status.built)}` : '–' }}<template v-if="run.db_status?.reason"> · {{ run.db_status.reason }}</template></dd></div>
        <div><dt>Report</dt><dd>{{ run.notify_status || 'not sent' }}</dd></div>
      </dl>
      <pre v-if="run.error" class="cmd">{{ run.error }}</pre>

      <h3>Hosts in this run</h3>
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Host</th><th>Result</th><th>Findings</th><th>Problems</th></tr></thead>
          <tbody>
            <tr v-for="sys in run.systems" :key="sys.system_id">
              <td class="strong">{{ sys.system_name }}</td>
              <td><span :class="['badge', sys.status === 'ok' ? 'ok' : 'danger']">{{ sys.status === 'ok' ? 'OK' : label('fehler') }}</span></td>
              <td>{{ fmtNum(sys.findings_count) }}</td>
              <td>
                <span v-if="sys.error" class="detail-text">{{ sys.error }}</span>
                <span v-for="(err, img) in sys.image_errors || {}" :key="img" class="detail-text">image {{ img.slice(7, 19) }}: {{ err }}</span>
                <span v-if="!sys.error && !Object.keys(sys.image_errors || {}).length" class="subtext">none</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="!run.systems?.length" class="hint">No host results recorded for this run.</p>
    </template>
    <template #actions>
      <slot name="actions" />
    </template>
  </Modal>
</template>

<style scoped>
.facts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.75rem; margin: 0 0 1rem; }
.facts-grid > div { padding: 0.75rem; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--ground); }
.facts-grid dt { font-size: 0.6875rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); }
.facts-grid dd { margin: 0.25rem 0 0; color: var(--text-2); word-break: break-word; }
</style>
