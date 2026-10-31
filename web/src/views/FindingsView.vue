<script setup>
import { label, fmtNum as fmt } from '../labels.js'
import { onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api.js'
import { useLive } from '../live.js'
import Icon from '../components/Icon.vue'
import Modal from '../components/Modal.vue'

const route = useRoute()
const router = useRouter()
const PAGE = 100
const SEVERITIES = [['', 'All'], ['kritisch', 'Critical'], ['hoch', 'High'], ['mittel', 'Medium'], ['info', 'Info']]
const total = ref(0)
const offset = ref(0)
const counts = ref(null)

const findings = ref([])
const loading = ref(false)
const error = ref('')

const filterSeverity = ref(route.query.severity || '')
const filterStatus = ref(route.query.status || 'open')
const filterSource = ref(route.query.source || '')
const onlyKev = ref(route.query.kev === 'true')
const onlyExposed = ref(false)
const onlyFix = ref(route.query.has_fix === 'true')
// Fix jetzt einspielbar: Host-Paketupdate oder neueres Image (Übersicht „Fixable now“)
const onlyFixable = ref(route.query.fixable === 'true')
// Aus „What to do“ auf der Übersicht: Funde eines Hosts (ohne eigenes Auswahlfeld, bleibt bis zum nächsten Filter)
const systemId = ref(route.query.system_id || '')
const SOURCES = [['', 'All sources'], ['scanner', 'Scanners (Grype/OSV)'], ['osv', 'OSV only'], ['both', 'Both scanners'],
  ['products', 'Versions & EOL'], ['appliances', 'Devices via API'], ['npm', 'TLS certificates'], ['ai', 'AI early warning']]
const SOURCE_LABELS = { grype: 'Grype', osv: 'OSV only', both: 'Grype + OSV', registry: 'Registry', eol: 'endoflife.date', npm: 'NPM certificate', ai: 'AI', truenas: 'TrueNAS', homeassistant: 'Home Assistant', proxmox: 'Proxmox VE', synology: 'Synology DSM', opnsense: 'OPNsense' }
// Eigene Funde haben keine NVD-Seite: Registry/EOL/Frühwarnung verlinken nicht auf NVD
const nvdLink = (f) => (f.cve_id.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${f.cve_id}` : null)
const query = ref(route.query.q || '')

// Empfohlene Maßnahme je Fund (vom Server, feste Regeln): aufklappbar unter der Zeile
const openAction = ref(null)
const copied = ref(null)
async function copyCommand(f) {
  try {
    await navigator.clipboard.writeText(f.action.command)
    copied.value = f.id
    setTimeout(() => { if (copied.value === f.id) copied.value = null }, 1600)
  } catch { /* ohne Clipboard-Rechte bleibt der Befehl markierbar */ }
}

// Snooze: zurückstellen bis zu einem Datum (max. 180 Tage), mit Grund; endet von selbst bei KEV, höherer Einstufung, Fix
const showSnoozeModal = ref(false)
const selectedFinding = ref(null)
const snoozeReason = ref('')
const snoozeScope = ref('occurrence')
const snoozeUntil = ref('')
const snoozeError = ref('')
const snoozeSaving = ref(false)
const isoDay = (days) => new Date(Date.now() + days * 86400000).toISOString().slice(0, 10)

async function loadFindings() {
  loading.value = true
  error.value = ''
  try {
    const params = new URLSearchParams({ status: filterStatus.value, limit: PAGE, offset: offset.value })
    if (filterSeverity.value) params.set('severity', filterSeverity.value)
    if (query.value) params.set('q', query.value)
    if (filterSource.value) params.set('source', filterSource.value)
    if (systemId.value) params.set('system_id', systemId.value)
    if (onlyKev.value) params.set('kev', 'true')
    if (onlyExposed.value) params.set('exposed', 'true')
    if (onlyFix.value) params.set('has_fix', 'true')
    if (onlyFixable.value) params.set('fixable', 'true')
    const res = await api.page(`/api/findings?${params}`)
    findings.value = res.items
    total.value = res.total
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

function openSnooze(finding) {
  selectedFinding.value = finding
  snoozeReason.value = ''
  snoozeScope.value = 'occurrence'
  snoozeUntil.value = isoDay(30)
  snoozeError.value = ''
  showSnoozeModal.value = true
}

async function submitSnooze() {
  if (!snoozeReason.value || snoozeReason.value.length < 3) {
    snoozeError.value = 'Please give a meaningful reason.'
    return
  }
  snoozeSaving.value = true
  snoozeError.value = ''
  try {
    await api.post(`/api/findings/${selectedFinding.value.id}/snooze`, {
      scope: snoozeScope.value,
      until: snoozeUntil.value,
      reason: snoozeReason.value,
    })
    showSnoozeModal.value = false
    await loadFindings()
  } catch (e) {
    snoozeError.value = e.message
  } finally {
    snoozeSaving.value = false
  }
}

function sevBadge(sev) {
  return `badge-sev ${sev}`
}

function applyFilters() {
  offset.value = 0
  systemId.value = ''
  router.replace({ query: { ...(filterSeverity.value && { severity: filterSeverity.value }), ...(query.value && { q: query.value }),
    ...(filterSource.value && { source: filterSource.value }) } })
  loadFindings()
}

function setSeverity(v) {
  filterSeverity.value = v
  applyFilters()
}

function page(dir) {
  offset.value = Math.max(0, offset.value + dir * PAGE)
  loadFindings()
}

// Suche aus der Kopfleiste
watch(() => route.query.q, (q) => {
  if ((q || '') !== query.value) {
    query.value = q || ''
    offset.value = 0
    loadFindings()
  }
})

const targetLabel = (t) => (t === 'host' ? 'Host packages' : t.replace(/^image:/, ''))

useLive(['findings'], () => loadFindings(), 1500)

onMounted(async () => {
  loadFindings()
  try { counts.value = (await api.get('/api/overview')).findings } catch { /* Zähler sind optional */ }
})
</script>

<template>
  <div class="header-row">
    <div>
      <h1>Findings</h1>
      <p class="subtitle">Vulnerabilities in host packages and container images, most urgent first</p>
    </div>
  </div>

  <p v-if="error" class="message error" role="alert">{{ error }}</p>

  <section class="card">
    <div class="toolbar">
      <div class="seg" role="tablist" aria-label="Severity">
        <button v-for="[v, l] in SEVERITIES" :key="v" role="tab" :aria-selected="filterSeverity === v"
                :class="['seg-btn', v, { active: filterSeverity === v }]" @click="setSeverity(v)">
          <i v-if="v" class="dot" />{{ l }}<span v-if="counts && v" class="count">{{ fmt(counts[v]) }}</span>
        </button>
      </div>
      <form class="filter-search" role="search" @submit.prevent="applyFilters">
        <Icon name="search" />
        <input v-model="query" type="search" placeholder="Filter by CVE, package, image or host" aria-label="Filter findings" @search="applyFilters" />
      </form>
      <select v-model="filterStatus" aria-label="Status" @change="applyFilters">
        <option value="open">Open</option>
        <option value="accepted">Snoozed</option>
        <option value="all">All</option>
      </select>
      <select v-model="filterSource" aria-label="Source" @change="applyFilters">
        <option v-for="[v, l] in SOURCES" :key="v" :value="v">{{ l }}</option>
      </select>
      <label class="chk"><input v-model="onlyKev" type="checkbox" @change="applyFilters" />KEV</label>
      <label class="chk"><input v-model="onlyExposed" type="checkbox" @change="applyFilters" />Internet-exposed</label>
      <label class="chk"><input v-model="onlyFix" type="checkbox" @change="applyFilters" />Fix available</label>
      <label class="chk" title="An update fixes it now: host package update or a newer image for the tag"><input v-model="onlyFixable" type="checkbox" @change="applyFilters" />Fixable now</label>
    </div>

    <div v-if="loading && !findings.length" class="empty">Loading findings…</div>
    <div v-else-if="findings.length" class="table-wrap" :class="{ stale: loading }">
      <table class="data-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>CVE</th>
            <th>Component</th>
            <th>Where</th>
            <th class="num" title="CVSS base score, below: EPSS exploit probability">Score</th>
            <th>Fix</th>
            <th>Status</th>
            <th><span class="sr-only">Action</span></th>
          </tr>
        </thead>
        <tbody>
          <template v-for="f in findings" :key="f.id">
          <tr :class="{ expanded: openAction === f.id }">
            <td>
              <span :class="sevBadge(f.severity)">{{ label(f.severity) }}</span>
              <span v-if="f.kev" class="badge-kev" title="Known exploited (CISA KEV)">KEV</span>
              <span v-if="f.internet_exposed" class="badge-kev exposed" title="Reachable from the internet (NPM or marked by hand)">NET</span>
            </td>
            <td>
              <a v-if="nvdLink(f)" class="cve" :href="nvdLink(f)" target="_blank" rel="noopener">
                {{ f.cve_id }}<Icon name="external" :size="12" />
              </a>
              <span v-else class="cve mono" :title="f.title">{{ f.cve_id }}</span>
              <span class="subtext">{{ SOURCE_LABELS[f.source] || f.source }}</span>
            </td>
            <td>
              <span class="strong truncate comp" :title="f.component">{{ f.component }}</span>
              <span class="subtext mono">{{ f.installed_version }}</span>
            </td>
            <td>
              <span class="strong">{{ f.system_name }}</span>
              <span class="subtext truncate" :title="targetLabel(f.target)">{{ targetLabel(f.target) }}</span>
            </td>
            <td class="num">
              {{ f.cvss_score > 0 ? f.cvss_score.toFixed(1) : '–' }}
              <span class="subtext">{{ (f.epss_score * 100).toFixed(1) }}%</span>
            </td>
            <td>
              <span v-if="f.fixed_version" class="mono text-success truncate fix" :title="f.fixed_version">{{ f.fixed_version }}</span>
              <span v-else class="text-muted">none yet</span>
            </td>
            <td>
              <span v-if="f.status === 'accepted'" class="badge accepted" :title="`Until ${f.accepted_until?.slice(0, 10)}: ${f.accepted_reason}`">Snoozed</span>
              <span v-else class="badge open">Open</span>
            </td>
            <td class="row-action">
              <button v-if="f.action" class="btn-sm" :aria-expanded="openAction === f.id" @click="openAction = openAction === f.id ? null : f.id">How to fix</button>
              <button v-if="f.status === 'open'" class="btn-sm" data-test="snooze" @click="openSnooze(f)">Snooze</button>
              <span v-else class="subtext">until {{ f.accepted_until?.slice(0, 10) }}</span>
            </td>
          </tr>
          <tr v-if="openAction === f.id" class="action-row">
            <td colspan="8">
              <p class="action-text">{{ f.action.text }}</p>
              <span v-if="f.action.command" class="action-cmd">
                <code class="mono">{{ f.action.command }}</code>
                <button class="btn-sm" @click="copyCommand(f)"><Icon :name="copied === f.id ? 'check' : 'copy'" :size="13" />{{ copied === f.id ? 'Copied' : 'Copy' }}</button>
              </span>
              <span v-if="f.action.command" class="subtext">Run it on {{ f.system_name }}. General advice: check it fits your setup before running it.</span>
            </td>
          </tr>
          </template>
        </tbody>
      </table>
    </div>
    <div v-else class="empty">No findings match these filters.</div>

    <footer v-if="total > 0" class="pager">
      <span>{{ fmt(offset + 1) }}–{{ fmt(Math.min(offset + findings.length, total)) }} of {{ fmt(total) }}</span>
      <div class="actions">
        <button class="btn-sm" :disabled="offset === 0 || loading" @click="page(-1)">Previous</button>
        <button class="btn-sm" :disabled="offset + PAGE >= total || loading" @click="page(1)">Next</button>
      </div>
    </footer>
  </section>

  <!-- Snooze -->
  <Modal v-if="showSnoozeModal" :footer="false" @close="showSnoozeModal = false">
    <h2>Snooze {{ selectedFinding?.cve_id }}</h2>
    <p class="subtitle">System: {{ selectedFinding?.system_name }} · Component: {{ selectedFinding?.component }}</p>

    <p v-if="snoozeError" class="message error">{{ snoozeError }}</p>

    <form class="snooze" @submit.prevent="submitSnooze">
      <fieldset>
        <legend>Applies to</legend>
        <label class="radio"><input v-model="snoozeScope" type="radio" name="snooze_scope" value="occurrence" />
          only this occurrence ({{ selectedFinding?.system_name }}{{ selectedFinding?.target !== 'host' ? ', this image in any version' : '' }})</label>
        <label class="radio"><input v-model="snoozeScope" type="radio" name="snooze_scope" value="everywhere" />
          everywhere: this CVE in {{ selectedFinding?.component }} on all systems, also new ones</label>
      </fieldset>

      <label>
        Until (max. 180 days):
        <input v-model="snoozeUntil" type="date" name="snooze_until" required :min="isoDay(1)" :max="isoDay(180)" />
      </label>

      <label>
        Required reason (why can this wait?):
        <textarea v-model="snoozeReason" name="snooze_reason" rows="3" required placeholder="e.g. service only reachable in an isolated VLAN; patch planned for next maintenance window." />
      </label>

      <p class="subtext">The finding stays in every report under "Snoozed" and no longer raises the alert level. It comes back by itself on that date, or earlier if the CVE lands on the KEV list, its rating goes up, or a fix appears.</p>

      <div class="modal-actions">
        <button type="button" class="secondary" @click="showSnoozeModal = false">Cancel</button>
        <button type="submit" class="primary" :disabled="snoozeSaving">
          {{ snoozeSaving ? 'Saving…' : 'Snooze' }}
        </button>
      </div>
    </form>
  </Modal>
</template>

<style scoped>
.snooze fieldset { border: 0; padding: 0; margin: 0 0 1rem; }
.snooze legend { font-size: 0.8125rem; margin-bottom: 0.25rem; }
.snooze .radio { display: flex; gap: 0.5rem; align-items: baseline; font-size: 0.875rem; margin-bottom: 0.25rem; }
.snooze .radio input { width: auto; }
.toolbar { display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; margin-bottom: 1rem; }
.toolbar select { width: auto; }
.chk { display: inline-flex; align-items: center; gap: 0.25rem; font-size: 0.8125rem; color: var(--muted); white-space: nowrap; }
.chk input { width: auto; margin: 0; }
.badge-kev.exposed { color: var(--high); }
.filter-search {
  flex: 1; min-width: 220px; display: flex; flex-direction: row; align-items: center; gap: 0.5rem;
  padding: 0 0.75rem; border: 1px solid var(--line-strong); border-radius: var(--radius-pill); background: var(--surface); color: var(--muted);
  transition: all 0.15s;
}
.filter-search:focus-within { border-color: var(--text-2); background: var(--surface-2); box-shadow: 0 0 0 3px rgba(255, 255, 255, 0.05); }
.filter-search input { flex: 1; border: none; background: none; padding: 0; min-height: 36px; color: var(--text); font-size: 0.8125rem; }
.filter-search input:focus-visible { outline: none; }
.cve { display: inline-flex; align-items: center; gap: 0.25rem; font: 500 0.8125rem var(--mono); color: var(--text); text-decoration: none; white-space: nowrap; }
.cve svg { color: var(--muted); }
.cve:hover { text-decoration: underline; }
.num { text-align: right; font-family: var(--mono); font-size: 0.8125rem; white-space: nowrap; }
.row-action { text-align: right; white-space: nowrap; }
.row-action .btn-sm + .btn-sm { margin-left: 0.25rem; }
tr.expanded td { border-bottom-color: transparent; }
.action-row td { padding-top: 0; background: var(--surface-2); }
.action-text { margin: 0.5rem 0 0.5rem; font-size: 0.875rem; color: var(--text-2); max-width: 100ch; line-height: 1.5; white-space: normal; }
.action-cmd { display: flex; align-items: center; gap: 0.25rem; max-width: 80ch; margin-bottom: 0.25rem; padding: 0.25rem 0.25rem 0.25rem 0.5rem;
  border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface); }
.action-cmd code { flex: 1; min-width: 0; overflow-x: auto; white-space: nowrap; font-size: 0.75rem; color: var(--text); }
.comp { max-width: 32ch; }
.fix { max-width: 18ch; }
td .truncate { max-width: 28ch; }
.stale { opacity: 0.55; transition: opacity 0.2s; }
.pager { display: flex; justify-content: space-between; align-items: center; gap: 1rem; padding-top: 1rem; margin-top: 0.5rem; border-top: 1px solid var(--line); color: var(--muted); font-size: 0.8125rem; }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
</style>
