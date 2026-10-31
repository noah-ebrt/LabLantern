<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { useLive } from '../live.js'
import { APPLIANCE_KINDS, CHECKS, POSTURE, RUN_TRIGGER, checkClass, fmtNum as fmt, hostState, hostVersion, label, runLabel } from '../labels.js'
import { useScanTrigger } from '../runSteps.js'
import { ago, fmtClock, fmtDateTime, fmtDay, fmtWeekdayTime } from '../time.js'
import Icon from '../components/Icon.vue'
import RunProgress from '../components/RunProgress.vue'
import PipelineFlow from '../components/PipelineFlow.vue'
import ConnectorDetailModal from '../components/ConnectorDetailModal.vue'
import StorageView from '../components/StorageView.vue'
import { countsText } from '../storage.js'
import ExposureSourceModal from '../components/ExposureSourceModal.vue'
import GuestCoverage from '../components/GuestCoverage.vue'
import HostDetailModal from '../components/HostDetailModal.vue'

const data = ref(null)
const runs = ref([])
const systems = ref([])
// NAS mit Pools oder Laufwerken (TrueNAS, Synology, Proxmox): Laufwerkssymbole in der Speicher-Karte
const nas = computed(() => systems.value.filter((s) => s.connector?.storage?.disks?.length || s.connector?.storage?.pools))
const error = ref('')
const progress = ref(null)
const hover = ref(null)

const LEVELS = [
  { key: 'kritisch', label: 'Critical', hint: 'KEV, high EPSS or exposed' },
  { key: 'hoch', label: 'High', hint: 'fix soon' },
  { key: 'mittel', label: 'Medium', hint: 'routine updates' },
  { key: 'info', label: 'Info', hint: 'negligible / unfixed upstream' },
]

async function loadData() {
  try {
    const [o, r, s] = await Promise.all([api.get('/api/overview'), api.get('/api/runs'), api.get('/api/systems')])
    data.value = o
    runs.value = r
    systems.value = s
  } catch (e) {
    error.value = e.message
  }
}

const { triggering, message: triggerMessage, trigger: triggerScan } = useScanTrigger({
  after: async () => { await loadData(); progress.value?.refresh() },
  error,
})

// Abgeschlossene Läufe mit Zahlen, älteste zuerst (für Mini-Balken und Verlauf)
const history = computed(() =>
  runs.value
    .filter((r) => r.summary_counts && Object.keys(r.summary_counts).length)
    .sort((a, b) => a.id - b.id)
    .slice(-14),
)

function series(key) {
  const vals = history.value.map((r) => r.summary_counts[key] || 0)
  const max = Math.max(1, ...vals)
  return vals.map((v) => Math.max(6, Math.round((v / max) * 100)))
}

function delta(key) {
  const h = history.value
  if (h.length < 2) return null
  return (h.at(-1).summary_counts[key] || 0) - (h.at(-2).summary_counts[key] || 0)
}

const trend = computed(() => {
  const rows = history.value.map((r) => ({
    id: r.id, at: r.started_at, trigger: r.trigger, status: r.status,
    crit: r.summary_counts.kritisch || 0, high: r.summary_counts.hoch || 0,
  }))
  const max = Math.max(1, ...rows.map((r) => r.crit + r.high))
  const step = Math.pow(10, Math.floor(Math.log10(max)))
  const top = Math.ceil(max / step) * step
  return { rows, top, ticks: [top, Math.round(top / 2), 0] }
})

const posture = computed(() => POSTURE[data.value?.ampel] ?? { text: '–', cls: 'neutral' })
// Davon jetzt per Update behebbar (Host-Paket oder neueres Image); der Rest wartet auf Upstream
const fixable = computed(() => data.value?.fixable || {})
const fixableTotal = computed(() => Object.values(fixable.value).reduce((a, b) => a + b, 0))

// Was hinter „Action needed“ steckt: Schritte vom Server (gleiche Regeln wie die Ampel), wichtigste zuerst
const STEPS_SHOWN = 6
const allSteps = ref(false)
const steps = computed(() => (data.value?.next_steps || []).filter((st) => !st.done))
// Abgehakt: verborgen bis zum nächsten Lauf; der löst den Schritt auf oder zeigt ihn wieder
const doneSteps = computed(() => (data.value?.next_steps || []).filter((st) => st.done))
const showDone = ref(false)
const shownSteps = computed(() => (allSteps.value ? steps.value : steps.value.slice(0, STEPS_SHOWN)))
async function markDone(st, done = true) {
  try {
    await api.post('/api/overview/steps/done', { id: st.id, done })
    await loadData()
  } catch (e) {
    error.value = e.message
  }
}
// Frühwarnungen, die eigene Systeme betreffen: eigene Leiste unter dem Zustand
const ewHits = computed(() => data.value?.early_warning_hits || [])
// Updates: neuer Agent freigegeben oder Sicherheitsupdates auf Hosts
const upd = computed(() => data.value?.updates || { agent_outdated: [], security: [] })
const updLink = computed(() => {
  const hosts = [...upd.value.security, ...upd.value.agent_outdated]
  const one = new Set(hosts.map((h) => h.id)).size === 1
  return one ? { path: '/systeme', query: { open: String(hosts[0].id) } } : { path: '/systeme' }
})
const ewSystems = computed(() => [...new Set(ewHits.value.flatMap((w) => w.systems))])
const copiedStep = ref(-1)
async function copyStep(i, text) {
  try {
    await navigator.clipboard.writeText(text)
    copiedStep.value = i
    setTimeout(() => { if (copiedStep.value === i) copiedStep.value = -1 }, 1600)
  } catch { /* ohne Clipboard-Rechte bleibt der Befehl markierbar */ }
}

// Detailansicht einer Matrixzeile: woher jede Bewertung kommt
const detail = ref(null)
const source = ref(null)


onMounted(loadData)
// Während eines Scans kommen viele Commits: gesammelt höchstens einmal pro Sekunde nachladen
useLive(['systems', 'runs', 'findings', 'settings'], loadData, 1000)
</script>

<template>
  <div class="header-row">
    <div>
      <h1>Overview</h1>
      <p class="subtitle">
        <template v-if="data?.last_run">Last run {{ fmtDateTime(data.last_run.started_at) }}</template>
        <template v-else>Security posture across all hosts</template>
      </p>
    </div>
    <div>
      <button class="primary" :disabled="triggering || !!data?.active_run" title="Complete run: ask every agent for fresh data, scan, check versions and AI early warnings" @click="triggerScan('full')">
        <Icon name="play" :size="14" />
        {{ data?.active_run ? 'Scan running…' : triggering ? 'Queuing…' : 'Scan now' }}
      </button>
    </div>
  </div>

  <p v-if="error" class="message error" role="alert">{{ error }}</p>
  <p v-if="triggerMessage" class="message success" role="status">{{ triggerMessage }}</p>
  <RunProgress ref="progress" @done="loadData" />

  <template v-if="data">
    <section v-if="data.reports_paused_until" class="notice" data-test="reports-paused">
      <strong>Reports paused until {{ data.reports_paused_until }}.</strong>
      Alerts and errors still go out.
      <RouterLink to="/einstellungen?tab=alerts#set-pause">Change</RouterLink>
    </section>
    <section v-for="h in data.setup_hints.filter((x) => !x.done)" :key="h.id" class="notice">
      <strong>Next step:</strong>
      <template v-if="h.id === 'notifications'">set up a notification channel so reports and alerts reach you.</template>
      <RouterLink :to="h.id === 'notifications' ? '/einstellungen?tab=alerts' : '/einstellungen'">Open settings</RouterLink>
    </section>

    <section class="posture card">
      <span :class="['badge', posture.cls]">{{ posture.text }}</span>
      <span class="posture-meta">
        Canary <strong :class="data.canary_status === 'ok' ? 'text-success' : 'text-danger'">{{ data.canary_status === 'ok' ? 'passed' : 'failed' }}</strong>
        <span class="sep" />Coverage <strong>{{ data.coverage_percent }}%</strong>
        <span class="sep" />Next run <strong>{{ data.next_run ? fmtWeekdayTime(data.next_run) : 'disabled' }}</strong>
        <span class="sep" /><RouterLink :to="{ path: '/funde', query: { fixable: 'true' } }" class="fixable-link"
          title="Open findings an update fixes now: host package update or a newer image for the tag">Fixable now
          <strong :class="fixableTotal ? 'text-danger' : 'text-success'">{{ fmt(fixableTotal) }}</strong></RouterLink>
        <span class="sep" />Worker <strong>{{ data.worker.age_seconds === null ? 'never seen' : data.worker.age_seconds < 120 ? 'active' : `${Math.round(data.worker.age_seconds / 60)} min ago` }}</strong>
      </span>
    </section>

    <RouterLink v-if="upd.agent_outdated.length || upd.security.length" :to="updLink" class="ew-bar card warning upd-bar">
      <span class="badge warning">Updates available</span>
      <span class="ew-titles">
        <template v-if="upd.security.length">Security updates: {{ upd.security.map((h) => `${h.name} (${h.count})`).join(', ') }}</template>
        <template v-if="upd.security.length && upd.agent_outdated.length"> · </template>
        <template v-if="upd.agent_outdated.length">Agent v{{ upd.agent_version }} for {{ upd.agent_outdated.map((h) => h.name).join(', ') }}</template>
      </span>
      <span class="ew-open">Open<Icon name="chevron" :size="14" /></span>
    </RouterLink>
    <RouterLink v-if="ewHits.length" :to="{ path: '/fruehwarnungen', query: { status: 'betroffen' } }"
                :class="['ew-bar', 'card', ewHits.some((w) => w.severity === 'hoch') ? 'danger' : 'warning']">
      <span :class="['badge', ewHits.some((w) => w.severity === 'hoch') ? 'danger' : 'warning']">
        {{ ewHits.length }} early warning{{ ewHits.length > 1 ? 's' : '' }} affect{{ ewHits.length > 1 ? '' : 's' }} your systems</span>
      <span class="ew-titles">{{ ewHits.slice(0, 3).map((w) => w.title).join(' · ') }}<template v-if="ewHits.length > 3"> · {{ ewHits.length - 3 }} more</template></span>
      <span v-if="ewSystems.length" class="ew-systems">{{ ewSystems.join(', ') }}</span>
      <span class="ew-open">Open<Icon name="chevron" :size="14" /></span>
    </RouterLink>

    

    <p v-if="data.snoozed_count" class="subtext snoozed-note" data-test="snoozed">
      {{ fmt(data.snoozed_count) }} findings snoozed: not counted below, still listed in every report.
      <RouterLink :to="{ path: '/funde', query: { status: 'accepted' } }">Show them</RouterLink>
    </p>
    <section class="kpis">
      <RouterLink v-for="l in LEVELS" :key="l.key" :to="{ path: '/funde', query: { severity: l.key } }" class="kpi card" :class="l.key">
        <div class="kpi-header-row">
          <span class="kpi-label"><i class="dot" />{{ l.label }}</span>
          <div class="kpi-glyph" aria-hidden="true">
            <Icon :name="l.key === 'kritisch' || l.key === 'hoch' ? 'shield' : 'findings'" :size="16" />
          </div>
        </div>
        <div class="kpi-center">
          <span class="kpi-value">{{ fmt(data.findings[l.key]) }}</span>
          <div class="host-c" aria-hidden="true">
            <i v-for="(h, i) in series(l.key)" :key="i" :style="{ height: h + '%' }" :class="{ last: i === series(l.key).length - 1 }" />
          </div>
        </div>
        <span :class="['kpi-fixable', { none: !fixable[l.key] }]">
          {{ fixable[l.key] ? `${fmt(fixable[l.key])} fixable now` : data.findings[l.key] ? 'none fixable now, waiting on upstream' : 'nothing open' }}
        </span>
        <div class="kpi-foot">
          <span v-if="delta(l.key) !== null" :class="['delta-pill', { up: delta(l.key) > 0, down: delta(l.key) < 0, neutral: delta(l.key) === 0 }]">
            {{ delta(l.key) > 0 ? '+' : '' }}{{ fmt(delta(l.key)) }} vs last run
          </span>
          <span v-else class="delta-pill neutral">Current run</span>
          <span class="kpi-hint">{{ l.hint }}</span>
        </div>
      </RouterLink>
    </section>

    <section class="split">
      <div class="card trend">
        <div class="card-header">
          <h2 class="panel-title">Critical &amp; high per run</h2>
          <span class="legend"><i class="crit" />Critical <i class="high" />High</span>
        </div>
        <div v-if="trend.rows.length" class="chart">
          <div class="y-axis"><span v-for="t in trend.ticks" :key="t">{{ fmt(t) }}</span></div>
          <div class="plot">
            <div class="gridlines"><i /><i /><i /></div>
            <div class="bars">
              <div v-for="(r, i) in trend.rows" :key="r.id" class="col" tabindex="0"
                   @mouseenter="hover = r" @mouseleave="hover = null" @focus="hover = r" @blur="hover = null">
                <div class="stack" :style="{ height: ((r.crit + r.high) / trend.top) * 100 + '%' }">
                  <i class="crit" :style="{ flexGrow: r.crit }" /><i class="high" :style="{ flexGrow: r.high }" />
                </div>
                <span class="x">#{{ r.id }}</span>
                <div v-if="hover?.id === r.id" :class="['tip', { 'at-start': i < 2, 'at-end': i > trend.rows.length - 3 }]" role="tooltip">
                  <strong>Run #{{ r.id }} · {{ fmtDay(r.at) }}, {{ fmtClock(r.at) }}</strong>
                  <span><i class="crit" />Critical {{ fmt(r.crit) }}</span>
                  <span><i class="high" />High {{ fmt(r.high) }}</span>
                  <span class="tip-extra">{{ RUN_TRIGGER[r.trigger] || r.trigger }} · {{ String(runLabel(r.status) ?? '').toLowerCase() }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
        <p v-else class="empty">The trend appears after the first finished run.</p>
      </div>

      <div class="card hosts">
        <div class="card-header">
          <h2 class="panel-title">Hosts</h2>
          <RouterLink to="/systeme" class="more">Manage</RouterLink>
        </div>
        <ul v-if="systems.length">
          <li v-for="s in systems" :key="s.id">
            <i :class="['state', hostState(s).tone]" />
            <div class="host-main">
              <span class="strong">{{ s.name }}</span>
              <span class="subtext">{{ hostVersion(s) }} · {{ hostState(s).text }}</span>
            </div>
            <span class="host-age">{{ ago(s.age_hours) }}</span>
          </li>
        </ul>
        <p v-else class="empty">No agents yet.</p>
      </div>
    </section>

    <section v-if="nas.length" class="card storage-card" data-test="storage-card">
      <div class="card-header">
        <h2 class="panel-title">Storage</h2>
        <span class="subtext">{{ nas.reduce((n, s) => n + s.connector.storage.disks.length, 0) }} drives in {{ nas.length }} system{{ nas.length === 1 ? '' : 's' }}</span>
      </div>
      <ul class="nas-list">
        <li v-for="s in nas" :key="s.id">
          <button type="button" class="nas-name" :title="`Details for ${s.name}`" @click="detail = { status: 'connector', system_id: s.id }">
            <span class="strong">{{ s.name }}</span>
            <span class="subtext">{{ APPLIANCE_KINDS[s.connector.kind] }} · {{ countsText(s.connector.storage) }}</span>
          </button>
          <StorageView :storage="s.connector.storage" compact />
        </li>
      </ul>
    </section>

    <PipelineFlow :data="data" :systems="systems" :triggering="triggering" @trigger="triggerScan('latest')" @changed="loadData" />


<section v-if="steps.length || doneSteps.length" class="card steps" aria-labelledby="steps-title">
      <div class="card-header">
        <h2 id="steps-title" class="panel-title">What to do</h2>
        <span class="subtext">Most urgent first · actively exploited (KEV) before the rest</span>
      </div>
      <ol class="step-list">
        <li v-for="(st, i) in shownSteps" :key="i" :class="['step', st.level]">
          <i class="step-dot" aria-hidden="true" />
          <div class="step-main">
            <span class="step-title">{{ st.title }}</span>
            <p v-if="st.detail" class="step-detail">{{ st.detail }}</p>
            <span v-if="st.command" class="step-cmd">
              <code class="mono">{{ st.command }}</code>
              <button class="btn-sm" :aria-label="`Copy command for ${st.title}`" @click="copyStep(i, st.command)">
                <Icon :name="copiedStep === i ? 'check' : 'copy'" :size="13" />{{ copiedStep === i ? 'Copied' : 'Copy' }}
              </button>
            </span>
          </div>
          <div class="step-actions">
            <button v-if="st.action === 'scan'" class="btn-sm" :disabled="triggering || !!data?.active_run" @click="triggerScan('full')">{{ st.cta }}</button>
            <RouterLink v-else-if="st.link" class="btn-sm step-link" :to="st.link">{{ st.cta || 'Open' }}</RouterLink>
            <button class="btn-sm" title="Hide until the next run; it comes back if the next run still finds it" @click="markDone(st)">
              <Icon name="check" :size="13" />Done</button>
          </div>
        </li>
      </ol>
      <p v-if="!steps.length" class="subtext">All steps marked done. The next run shows whether they are resolved.</p>
      <button v-if="steps.length > STEPS_SHOWN" class="btn-link more" @click="allSteps = !allSteps">
        {{ allSteps ? 'Show fewer' : `Show ${steps.length - STEPS_SHOWN} more` }}
      </button>
      <div v-if="doneSteps.length" class="done-steps">
        <button class="btn-link" @click="showDone = !showDone">{{ showDone ? 'Hide' : 'Show' }} {{ doneSteps.length }} marked done</button>
        <span class="subtext">hidden until the next run, which resolves them or shows them again</span>
        <ul v-if="showDone">
          <li v-for="st in doneSteps" :key="st.id"><span>{{ st.title }}</span>
            <button class="btn-link" @click="markDone(st, false)">Undo</button></li>
        </ul>
      </div>
    </section>

    
    <section class="card">
      <div class="card-header">
        <h2 class="panel-title">Coverage · system × check</h2>
        <span class="hint">{{ data.coverage_percent }}% checked without error</span>
      </div>
      <div v-if="data.coverage.length" class="table-wrap">
        <table class="data-table matrix">
          <thead>
            <tr>
              <th>System</th>
              <th>Last report</th>
              <th v-for="[k, l] in CHECKS" :key="k">{{ l }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="sys in data.coverage" :key="sys.system_id" class="clickable" tabindex="0"
                :title="`Details for ${sys.system_name}`" @click="detail = sys" @keydown.enter="detail = sys">
              <td>
                <span class="strong row-link">{{ sys.system_name }}</span>
                <span v-if="sys.status === 'pending'" class="subtext">waiting for approval</span>
              </td>
              <td :class="{ 'text-danger': sys.is_stale }">{{ ago(sys.age_hours) }}</td>
              <td v-for="[k] in CHECKS" :key="k">
                <span :class="checkClass(sys.checks[k].status)">{{ label(sys.checks[k].status) }}</span>
                <span class="subtext truncate" :title="sys.checks[k].detail">{{ sys.checks[k].detail }}</span>
              </td>
            </tr>
          </tbody>
        </table>
        <p class="legend-line">
          <span class="badge ok">OK</span> checked, nothing to do
          <span class="badge warning">FINDING</span> needs attention
          <span class="badge danger">ERROR</span> could not be checked
          <span class="badge neutral">QUEUED</span> new data, checked in the next run · click a row for details
        </p>
      </div>
      <p v-else class="empty">No systems connected yet. <RouterLink to="/systeme">Add a Linux agent</RouterLink></p>
      <GuestCoverage v-if="data.guests?.length" :guests="data.guests" @changed="loadData()" />
      <div v-if="data.exposure_sources?.length" class="table-wrap" data-test="exposure-sources">
        <table class="data-table">
          <thead><tr><th>Exposure source</th><th>Status</th><th>Exposed</th><th>Not matched</th></tr></thead>
          <tbody>
            <tr v-for="src in data.exposure_sources" :key="src.key" class="clickable" tabindex="0"
                :title="`Details for ${src.label}`" @click="source = src" @keydown.enter="source = src">
              <td><span class="strong row-link">{{ src.label }}</span></td>
              <td>
                <span :class="checkClass(src.status)">{{ label(src.status) }}</span>
                <span class="subtext truncate" :title="src.detail">{{ src.detail }}</span>
              </td>
              <td>{{ src.exposed }}</td>
              <td>{{ src.unmatched }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </template>

  <ConnectorDetailModal v-if="detail?.status === 'connector'" :system-id="detail.system_id" @close="detail = null" />
  <HostDetailModal v-else-if="detail" :system-id="detail.system_id" @close="detail = null" @changed="loadData()" />
  <ExposureSourceModal v-if="source" :source="source" @close="source = null" />
</template>

<style scoped>
.storage-card .nas-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; }
.storage-card .nas-list li { display: grid; grid-template-columns: minmax(10rem, 14rem) 1fr; gap: 0.5rem 1.25rem; align-items: center;
  padding: 0.7rem 0; border-top: 1px solid var(--line); }
.storage-card .nas-list li:first-child { border-top: 0; }
.storage-card .nas-name { all: unset; display: flex; flex-direction: column; gap: 0.1rem; cursor: pointer; border-radius: 6px; }
.storage-card .nas-name:hover .strong { text-decoration: underline; }
.storage-card .nas-name:focus-visible { outline: 2px solid var(--info); outline-offset: 3px; }
@media (max-width: 640px) { .storage-card .nas-list li { grid-template-columns: 1fr; } }
.posture { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; padding: 0.75rem 1.1rem; }
.posture-meta { color: var(--muted); display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; font-size: 0.85rem; }
.posture-meta strong { color: var(--text); font-weight: 500; }
.sep { width: 1px; height: 14px; background: var(--line-strong); margin: 0 0.35rem; }

.steps { padding-bottom: 0.6rem; }
.step-list { list-style: none; margin: 0; padding: 0; }
.step { display: grid; grid-template-columns: 0.5rem minmax(0, 1fr) auto; gap: 0.2rem 0.85rem; align-items: start; padding: 0.75rem 0; border-top: 1px solid var(--line); }
.step:first-child { border-top: 0; padding-top: 0.25rem; }
.step-dot { width: 7px; height: 7px; margin-top: 0.45rem; border-radius: 50%; background: var(--muted); }
.step.rot .step-dot { background: var(--danger); }
.step.gelb .step-dot { background: var(--warn); }
.step-main { display: flex; flex-direction: column; gap: 0.3rem; min-width: 0; }
.step-title { color: var(--text); font-weight: 500; overflow-wrap: anywhere; }   /* Digests und Pfade ohne Leerzeichen */
.step-detail { margin: 0; font-size: 0.86rem; color: var(--text-2); line-height: 1.5; max-width: 90ch; overflow-wrap: anywhere; }
.step-cmd { display: flex; align-items: center; gap: 0.35rem; max-width: 70ch; padding: 0.3rem 0.35rem 0.3rem 0.6rem; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface-2); }
.step-cmd code { flex: 1; min-width: 0; overflow-x: auto; white-space: nowrap; font-size: 0.76rem; color: var(--text); }
/* Navigation bleibt ein Link, sieht aber aus wie die Schaltflächen daneben */
a.step-link { display: inline-flex; align-items: center; white-space: nowrap; text-decoration: none; font-weight: 500; color: var(--text); background: var(--surface-2); border: 1px solid var(--line-strong); border-radius: var(--radius-sm); }
a.step-link:hover { background: var(--surface-3); }
.more { margin-top: 0.35rem; }
.step-actions { display: flex; gap: 0.4rem; flex-wrap: wrap; justify-content: flex-end; }
.done-steps { margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid var(--line); display: flex; flex-wrap: wrap; gap: 0.2rem 0.6rem; align-items: baseline; }
.done-steps ul { flex-basis: 100%; list-style: none; margin: 0.3rem 0 0; padding: 0; font-size: 0.82rem; color: var(--text-2); }
.done-steps li { display: flex; gap: 0.6rem; padding: 0.15rem 0; }
/* Frühwarnungen: so auffällig wie die Zustandsleiste, ein Klick führt zur Seite */
.ew-bar { display: flex; align-items: center; gap: 0.5rem 1rem; flex-wrap: wrap; padding: 0.75rem 1.1rem; text-decoration: none; color: var(--text-2); font-size: 0.85rem; }
.ew-bar.danger { border-color: color-mix(in srgb, var(--danger) 45%, var(--line)); }
.ew-bar.warning { border-color: color-mix(in srgb, var(--warn) 45%, var(--line)); }
.ew-bar:hover { background: var(--surface-2); }
.ew-titles { flex: 1; min-width: 12rem; color: var(--text); }
.ew-systems { color: var(--muted); }
.ew-open { display: inline-flex; align-items: center; gap: 0.2rem; color: var(--text); font-weight: 500; }
@media (max-width: 720px) {
  .step { grid-template-columns: 0.5rem minmax(0, 1fr); }
  .step > .step-actions { grid-column: 2; justify-content: flex-start; }
}

.kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1rem; margin-bottom: 1.25rem; }
.kpi {
  margin: 0; padding: 1.2rem 1.35rem 1rem; text-decoration: none; color: inherit;
  display: flex; flex-direction: column; gap: 0.8rem;
  background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
  box-shadow: var(--shadow-card);
  transition: transform 0.18s ease, border-color 0.2s ease, background-color 0.2s ease;
}
.kpi:hover { border-color: var(--line-strong); background: var(--surface-2); transform: translateY(-2px); }
.kpi-header-row { display: flex; justify-content: space-between; align-items: center; }
.kpi-label { display: flex; align-items: center; gap: 0.45rem; font-size: 0.74rem; font-weight: 600; letter-spacing: 0.07em; text-transform: uppercase; color: var(--text-2); }
.kpi-glyph {
  display: flex; align-items: center; justify-content: center;
  width: 32px; height: 32px; border-radius: 8px;
  background: var(--surface-2); border: 1px solid var(--line);
  color: var(--c);
}
.kpi-center { display: flex; justify-content: space-between; align-items: flex-end; gap: 0.75rem; }
.kpi-value { font: 700 2.2rem/1 var(--font); letter-spacing: -0.03em; color: var(--text); }
.dot { width: 7px; height: 7px; border-radius: 50%; background: var(--c); flex-shrink: 0; }
.kpi.kritisch { --c: var(--crit); }
.kpi.hoch { --c: var(--high); }
.kpi.mittel { --c: var(--med); }
.kpi.info { --c: var(--info); }
.kpi.kritisch .kpi-value { color: var(--crit); }

.mini { display: flex; align-items: flex-end; gap: 3px; height: 32px; }
.mini i { width: 4px; border-radius: 999px; background: var(--surface-3); transform-origin: bottom; animation: grow 0.7s var(--ease) both; }
.mini i.last { background: var(--c); }
@keyframes grow { from { transform: scaleY(0.15); } }

.kpi-foot { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; font-size: 0.76rem; border-top: 1px solid var(--line); padding-top: 0.65rem; }
.kpi-fixable { font-size: 0.78rem; font-weight: 600; color: var(--c); }
.kpi-fixable.none { font-weight: 400; color: var(--muted); }
.fixable-link { color: inherit; text-decoration: none; }
.fixable-link:hover { text-decoration: underline; }
.kpi-hint { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.75rem; }
.delta-pill {
  display: inline-flex; align-items: center; gap: 0.3rem; padding: 0.12rem 0.55rem;
  border-radius: 999px; font-weight: 600; font-size: 0.72rem;
  background: var(--surface-2); color: var(--text-2); border: 1px solid var(--line-strong);
  white-space: nowrap;
}
.kpi.kritisch .delta-pill.up, .kpi.hoch .delta-pill.up {
  color: var(--crit); background: color-mix(in srgb, var(--crit) 12%, transparent); border-color: color-mix(in srgb, var(--crit) 30%, transparent);
}
.delta-pill.down {
  color: var(--ok); background: color-mix(in srgb, var(--ok) 12%, transparent); border-color: color-mix(in srgb, var(--ok) 30%, transparent);
}

.split { display: grid; grid-template-columns: minmax(0, 2fr) minmax(260px, 1fr); gap: 1rem; margin-bottom: 1rem; }
.split > .card { margin: 0; }
.legend { display: flex; align-items: center; gap: 0.4rem; font-size: 0.78rem; color: var(--muted); }
.legend i, .tip i { width: 8px; height: 8px; border-radius: 2px; display: inline-block; }
.legend i + * { margin-right: 0.5rem; }
i.crit { background: var(--crit); }
i.high { background: var(--high); }
.chart { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 0.75rem; height: 230px; }
.y-axis { display: flex; flex-direction: column; justify-content: space-between; font: 0.7rem var(--mono); color: var(--muted); text-align: right; padding-bottom: 22px; }
.plot { position: relative; }
.gridlines { position: absolute; inset: 0 0 22px; display: flex; flex-direction: column; justify-content: space-between; }
.gridlines i { border-top: 1px dashed var(--line); }
.bars { position: absolute; inset: 0; display: flex; gap: 6px; align-items: stretch; }
.col { position: relative; flex: 1; display: flex; flex-direction: column; justify-content: flex-end; align-items: center; padding-bottom: 22px; outline: none; }
.stack { width: min(100%, 26px); display: flex; flex-direction: column; border-radius: 4px 4px 2px 2px; overflow: hidden; min-height: 3px; transform-origin: bottom; animation: grow 0.8s var(--ease) both; transition: filter 0.15s; }
.stack i { display: block; min-height: 0; }
.stack i.high { opacity: 0.85; }
.col:hover .stack, .col:focus-visible .stack { filter: brightness(1.25); }
.col .x { position: absolute; bottom: 0; font: 0.68rem var(--mono); color: var(--muted); }
.tip {
  position: absolute; bottom: calc(100% - 10px); left: 50%; transform: translateX(-50%); z-index: 5;
  display: flex; flex-direction: column; gap: 0.2rem; white-space: nowrap; font-size: 0.78rem; color: var(--text-2);
  background: var(--surface-2); border: 1px solid var(--line-strong); border-radius: 8px; padding: 0.5rem 0.65rem;
  box-shadow: 0 12px 28px -8px rgb(0 0 0 / 0.6); pointer-events: none; animation: rise 0.18s var(--ease);
}
.tip .tip-extra { color: var(--muted); }
/* an den Rändern nach innen klappen, sonst schneidet die Karte den Tooltip ab */
.tip.at-start { left: 0; transform: none; }
.tip.at-end { left: auto; right: 0; transform: none; }
.tip strong { color: var(--text); font-weight: 500; }
.tip span { display: flex; align-items: center; gap: 0.4rem; }

.hosts ul { list-style: none; margin: 0; padding: 0; }
.hosts li { display: flex; align-items: center; gap: 0.75rem; padding: 0.6rem 0; border-bottom: 1px solid var(--line); }
.hosts li:last-child { border-bottom: none; }
.host-main { flex: 1; min-width: 0; }
.host-age { font-size: 0.78rem; color: var(--muted); white-space: nowrap; }
.state { width: 8px; height: 8px; border-radius: 50%; flex: none; background: var(--muted); }
.state.ok { background: var(--ok); box-shadow: 0 0 0 3px color-mix(in srgb, var(--ok) 18%, transparent); }
.state.warn { background: var(--warn); }
.more { font-size: 0.8rem; color: var(--text-2); }

.matrix td { min-width: 120px; }
.matrix td:first-child, .matrix td:nth-child(2) { min-width: 0; white-space: nowrap; }
.matrix .truncate { max-width: 32ch; margin-top: 0.3rem; }

@media (max-width: 1100px) {
  .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .split { grid-template-columns: minmax(0, 1fr); }
}
@media (max-width: 560px) {
  .kpis { grid-template-columns: minmax(0, 1fr); }
  .sep { display: none; }
  .posture-meta { gap: 0.35rem 1rem; }
  .chart { height: 190px; }
}
.state.bad { background: var(--danger); }
tr.clickable { cursor: pointer; }
tr.clickable:focus-visible { outline: 2px solid var(--text-2); outline-offset: -2px; }
.row-link { text-decoration: underline; text-decoration-color: var(--line-strong); text-underline-offset: 3px; }
</style>
