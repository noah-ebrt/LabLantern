<script setup>
import RunProgress from '../components/RunProgress.vue'
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import RunDetailModal from '../components/RunDetailModal.vue'
import { api } from '../api.js'
import { useLive } from '../live.js'
import { fmtDateTime } from '../time.js'
import { useScanTrigger } from '../runSteps.js'
import { runBadge, runLabel } from '../labels.js'

const runs = ref([])
const loading = ref(false)
const error = ref('')

async function loadRuns(silent = false) {
  if (!silent) {
    loading.value = true
    error.value = ''
  }
  try {
    runs.value = await api.get('/api/runs')
  } catch (e) {
    if (!silent) error.value = e.message
  } finally {
    loading.value = false
  }
}

const { triggering, message: triggerMsg, trigger: triggerScan } = useScanTrigger({ after: loadRuns, error })

// Details eines Laufs (auch per Link ?run=<id> aus der Übersicht)
const route = useRoute()
const runDetail = ref(null)
const openRun = (id) => { runDetail.value = id }

onMounted(() => {
  loadRuns()
  if (Number(route.query.run)) openRun(Number(route.query.run))
})
useLive(['runs'], () => loadRuns(true))
</script>

<template>
  <div class="header-row">
    <div>
      <h1>Scan runs</h1>
      <p class="subtitle">History of all scheduled and manual scan runs</p>
    </div>
    <div>
      <button class="primary" :disabled="triggering" @click="triggerScan">
        {{ triggering ? 'Queuing…' : 'Scan now' }}
      </button>
      <button @click="loadRuns">Refresh</button>
    </div>
  </div>

  <RunProgress @done="loadRuns" />
  <p v-if="error" class="message error" role="alert">{{ error }}</p>
  <p v-if="triggerMsg" class="message success" role="status">{{ triggerMsg }}</p>

  <div v-if="loading" class="empty">Loading runs…</div>

  <div v-else-if="runs.length" class="card">
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>Run</th>
            <th>Started</th>
            <th>Status</th>
            <th>Canary test</th>
            <th>Findings</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in runs" :key="r.id" class="clickable" tabindex="0" :title="`Details for run #${r.id}`"
            @click="openRun(r.id)" @keydown.enter="openRun(r.id)">
            <td class="strong">#{{ r.id }}</td>
            <td>{{ fmtDateTime(r.started_at) }}</td>
            <td>
              <span :class="runBadge(r.status)" :title="r.error">
                {{ runLabel(r.status) }}
              </span>
            </td>
            <td>
              <span :class="r.canary_status === 'ok' ? 'badge ok' : 'badge danger'">
                {{ r.canary_status === 'ok' ? 'Green (passed)' : r.canary_status === 'offen' ? 'pending' : 'Red (failed)' }}
              </span>
            </td>
            <td>
              <span class="counts">
                <span class="c-kritisch">Critical: {{ r.summary_counts?.kritisch || 0 }}</span> ·
                <span class="c-hoch">High: {{ r.summary_counts?.hoch || 0 }}</span> ·
                <span class="c-mittel">Medium: {{ r.summary_counts?.mittel || 0 }}</span>
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <div v-else class="card empty">
    No runs recorded yet.
    <button class="primary" @click="triggerScan">Start first run</button>
  </div>

  <RunDetailModal v-if="runDetail" :run-id="runDetail" @close="runDetail = null" />
</template>

<style scoped>

.counts { font-size: 0.8125rem; }
.c-kritisch { color: var(--crit); font-weight: 600; }
.c-hoch { color: var(--high); font-weight: 600; }
.c-mittel { color: var(--med); }
</style>
