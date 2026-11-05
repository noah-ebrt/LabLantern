<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '../api.js'
import { useLive } from '../live.js'
import { fmtDateTime, fmtDay, timeAgo } from '../time.js'
import Icon from '../components/Icon.vue'
import { label } from '../labels.js'

// KI-Frühwarnungen (PLAN Abschnitt 5): Feed-Einträge und Treffer der Web-Recherche mit Einstufung, Stufe und Schritten.
// Reihenfolge kommt vom Server: betroffen, unklar, wartend, nicht betroffen; darin höhere Stufe, dann neueste zuerst.
const STATUS = {
  betroffen: { cls: 'danger', text: 'Affected' },
  unklar: { cls: 'warning', text: 'Needs review' },
  pending: { cls: 'neutral', text: 'Queued' },
  behoben: { cls: 'ok', text: 'Fixed' },
  nicht_betroffen: { cls: 'ok', text: 'Not affected' },
}
const FILTERS = [['', 'All'], ['betroffen', 'Affected'], ['unklar', 'Needs review'], ['behoben', 'Fixed'], ['nicht_betroffen', 'Not affected']]
const EMPTY = {
  '': 'No early warnings yet. They appear when a feed mentions one of your products in the last 30 days.',
  betroffen: 'Nothing in the feeds affects your installed versions.',
  unklar: 'Nothing to review: every matched advisory could be compared with your installed versions.',
  behoben: 'Nothing fixed yet. An affected advisory moves here once every host runs a version outside its range.',
  nicht_betroffen: 'No advisory has been ruled out yet.',
}
// Behoben oder nicht betroffen: keine Stufe, keine Schritte, keine Abhilfe mehr
const done = (w) => w.status === 'nicht_betroffen' || w.status === 'behoben'

const filter = ref(useRoute()?.query.status || '')   // Link aus „What to do“ (/fruehwarnungen?status=betroffen)
const data = ref(null)
const loading = ref(true)
const error = ref('')
const checking = ref(false)
const showConfig = ref(false)
const feedsText = ref('')
const productsText = ref('')
const configMsg = ref(null)
const saving = ref(false)
const research = ref({ enabled: true, verify: true })
const copied = ref('')
let poll = null

async function load() {
  try {
    data.value = await api.get(`/api/early-warnings${filter.value ? `?status=${filter.value}` : ''}`)
    error.value = ''
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

// Gleicher Schritt auf mehreren Hosts: eine Zeile, alle Hosts davor
function steps(w) {
  const out = []
  for (const a of w.actions || []) {
    const same = out.find(x => x.text === a.text && x.command === a.command)
    if (same) same.system += `, ${a.system}`
    else out.push({ ...a })
  }
  return out
}

function setFilter(v) {
  filter.value = v
  load()
}

function toggleConfig() {
  if (!showConfig.value) {
    feedsText.value = (data.value?.feeds || []).join('\n')
    productsText.value = (data.value?.products || []).map((p) => [p.name, p.version, p.where].filter(Boolean).join(' | ')).join('\n')
    const enabled = data.value?.research?.enabled ?? true
    research.value = { enabled, verify: data.value?.research?.verify ?? enabled }
    configMsg.value = null
  }
  showConfig.value = !showConfig.value
}

async function saveConfig() {
  const products = productsText.value.split('\n').map((l) => l.split('|').map((x) => x.trim()))
    .filter(([n]) => n).map(([name, version = '', where = '']) => ({ name, version, where }))
  saving.value = true
  try {
    await api.put('/api/early-warnings/config', { feeds: feedsText.value.split('\n').map((x) => x.trim()).filter(Boolean), products })
    await api.put('/api/early-warnings/research', research.value)
    configMsg.value = { kind: 'ok', text: 'Saved. The next pass uses these feeds and products.' }
    await load()
  } catch (e) {
    configMsg.value = { kind: 'error', text: e.message }
  } finally {
    saving.value = false
  }
}

// Der Durchgang läuft im Hintergrund: warten, bis sein Zeitstempel sich ändert (höchstens 3 min, mit Recherche 6)
async function checkNow(withResearch = false) {
  const before = data.value?.state?.at
  checking.value = withResearch ? 'research' : 'feeds'
  error.value = ''
  try {
    await api.post(`/api/early-warnings/refresh${withResearch ? '?research=true' : ''}`)
    const started = Date.now()
    poll = setInterval(async () => {
      await load()
      if (data.value?.state?.at !== before || Date.now() - started > (withResearch ? 360000 : 180000)) stopPoll()
    }, 3000)
  } catch (e) {
    error.value = e.message
    checking.value = false
  }
}
function stopPoll() {
  clearInterval(poll)
  poll = null
  checking.value = false
}
onBeforeUnmount(() => poll && clearInterval(poll))

// Abdeckungsprüfung: läuft im Hintergrund (KEV und GitHub, unter einer Minute); danach neu laden
const coverageBusy = ref(false)
const coverage = computed(() => data.value?.coverage || null)
const STATUS_TEXT = { early: 'warned early', late: 'warned late', related: 'same product, no CVE', kev_only: 'only via KEV', missed: 'missed' }
const STATUS_LABEL = { early: 'Warned early', late: 'Warned late', related: 'Same product, no CVE', kev_only: 'Only via KEV', missed: 'Missed' }
const COUNT_KEYS = ['early', 'late', 'related', 'kev_only', 'missed']
// Farbe nur, wo etwas zu tun ist: verpasst rot, späte oder indirekte Treffer gelb, null gedämpft
const countTone = (k) => {
  const n = coverage.value?.counts?.[k] ?? 0
  if (!n) return 'zero'
  return k === 'missed' ? 'danger' : k === 'early' ? '' : 'warning'
}
// "Plex Media Server: CVE-2026-1 exploited" → "Plex Media Server"; die CVE steht daneben
const kevProduct = (r) => r.title.replace(/:\s*CVE-\d+-\d+.*$/i, '').trim() || r.title
const days = (n) => `${n} day${n === 1 ? '' : 's'}`
const coverageGaps = computed(() => (coverage.value?.kev || []).filter((r) => r.status !== 'early'))
const coveragePossible = computed(() => (coverage.value?.ghsa || []).filter((a) => a.status === 'possible'))
async function checkCoverage() {
  const before = coverage.value?.at
  coverageBusy.value = true
  error.value = ''
  try {
    await api.post('/api/early-warnings/coverage-check')
    const started = Date.now()
    const wait = setInterval(async () => {
      await load()
      if (coverage.value?.at !== before || Date.now() - started > 120000) {
        clearInterval(wait)
        coverageBusy.value = false
      }
    }, 3000)
  } catch (e) {
    error.value = e.message
    coverageBusy.value = false
  }
}

async function retry(w) {
  try {
    await api.post(`/api/early-warnings/${w.id}/retry`)
    await load()
  } catch (e) {
    error.value = e.message
  }
}

const state = computed(() => data.value?.state || {})
const counts = computed(() => data.value?.counts || {})
const total = computed(() => Object.values(counts.value).reduce((a, b) => a + b, 0))
const feedErrors = computed(() => Object.entries(state.value.feed_errors || {}).map(([url, err]) => {
  // Release-Feeds liegen alle auf github.com: dort zählt das Repo
  try { const u = new URL(url); return { host: u.hostname === 'github.com' ? u.pathname.replace(/\/releases\.atom$/, '').slice(1) : u.hostname, url, err } } catch { return { host: url, url, err } }
}))
const lastPass = computed(() => (state.value.at ? timeAgo(new Date(state.value.at * 1000).toISOString()) : 'never'))
// Gleiche Produkte auf mehreren Wegen gefunden: je Produkt und Host einmal
const where = (w) => [...new Map(w.matched.map((m) => [`${m.product}@${m.system}`, m])).values()]
const researchState = computed(() => data.value?.research?.state || {})
const researchText = computed(() => {
  const r = data.value?.research
  if (!r || !data.value.ai_configured) return null
  if (!r.enabled) return 'off'
  if (!researchState.value.at) return 'not run yet'
  return timeAgo(new Date(researchState.value.at * 1000).toISOString())
})

// Je Schaltfläche (Warnung und Schritt): gleiche Befehle auf mehreren Hosts zeigen „Copied“ nur dort, wo geklickt wurde
async function copy(id, text) {
  try {
    await navigator.clipboard.writeText(text)
    copied.value = id
    setTimeout(() => { if (copied.value === id) copied.value = '' }, 1600)
  } catch { /* ohne Clipboard-Rechte bleibt der Befehl markierbar */ }
}

onMounted(load)
useLive(['findings', 'settings'], load, 3000)
</script>

<template>
  <div class="header-row">
    <div>
      <h1>Early warnings</h1>
      <p class="subtitle">Global security news and a daily web search, narrowed to what you run, read by an AI and compared with your installed versions in code</p>
    </div>
    <div>
      <button class="secondary" :aria-expanded="showConfig" aria-controls="ew-config" @click="toggleConfig">
        <Icon name="settings" :size="15" />Feeds &amp; products
      </button>
      <button v-if="data?.ai_configured && data.research?.enabled" class="secondary" :disabled="!!checking"
              title="Let the AI search the web for fresh advisories on your products now" @click="checkNow(true)">
        <Icon name="search" :size="15" :class="{ spin: checking === 'research' }" />{{ checking === 'research' ? 'Researching…' : 'Research now' }}
      </button>
      <button class="primary" :disabled="!!checking" @click="checkNow()">
        <Icon name="refresh" :size="15" :class="{ spin: checking === 'feeds' }" />{{ checking === 'feeds' ? 'Checking feeds…' : 'Check feeds now' }}
      </button>
    </div>
  </div>
  <p v-if="error" class="message error" role="alert">{{ error }}</p>

  <section v-if="data" class="facts" aria-label="Status of the early warning">
    <span>Last pass <strong>{{ lastPass }}</strong></span>
    <span>Feeds <strong>{{ data.feeds.length }}</strong></span>
    <span>Products watched <strong>{{ state.keywords ?? '–' }}</strong></span>
    <span v-if="state.ai_calls != null">AI calls last pass <strong>{{ state.ai_calls }}</strong></span>
    <span v-if="researchText" :title="researchState.model ? `${researchState.model}, ${researchState.searches ?? 0} searches, ${researchState.sources ?? 0} sources` : ''">
      Web research <strong :class="{ 'text-danger': researchState.error }">{{ researchText }}</strong>
      <span v-if="researchState.error" class="text-danger"> – {{ researchState.error }}</span>
      <span v-else-if="researchState.ok"> · {{ researchState.new }} new</span>
    </span>
    <span>AI provider
      <strong v-if="data.ai_configured">configured</strong>
      <RouterLink v-else to="/einstellungen?tab=ai#set-ai-models" class="text-danger">none set – matched advisories need review by hand</RouterLink>
    </span>
  </section>

  <div v-if="feedErrors.length" class="notice" role="status">
    <Icon name="x" :size="15" />
    <div>
      <strong>{{ feedErrors.length === 1 ? 'A feed could not be read' : `${feedErrors.length} feeds could not be read` }}</strong>
      <span v-for="f in feedErrors" :key="f.url" class="subtext" :title="f.url">{{ f.host }}: {{ f.err }}</span>
    </div>
  </div>

  <div v-if="data?.health?.length" class="notice" role="alert" data-test="health">
    <Icon name="x" :size="15" />
    <div>
      <strong>The early warning is not working fully</strong>
      <span v-for="p in data.health" :key="p.key" class="subtext">{{ p.text }} <template v-if="p.since">(since {{ timeAgo(new Date(p.since * 1000).toISOString()) }})</template></span>
    </div>
  </div>

  <section v-if="data" class="card coverage" aria-label="Coverage check" data-test="coverage">
    <div class="coverage-head">
      <div>
        <h2>Coverage check</h2>
        <p v-if="coverage" class="subtext">
          Exploited issues (CISA KEV) for your products in the last {{ coverage.window_days }} days · checked {{ timeAgo(new Date(coverage.at * 1000).toISOString()) }}
        </p>
        <p v-else class="subtext">Not run yet. Once a week LabLantern checks whether the early warning caught every actively exploited issue for your products.</p>
        <p v-for="(e, src) in coverage?.errors || {}" :key="src" class="subtext text-danger">{{ e }}</p>
      </div>
      <button class="secondary btn-sm" :disabled="coverageBusy" data-test="coverage-now" @click="checkCoverage">
        <Icon name="refresh" :size="14" :class="{ spin: coverageBusy }" />{{ coverageBusy ? 'Checking…' : 'Check now' }}
      </button>
    </div>
    <dl v-if="coverage" class="coverage-counts">
      <div class="total"><dt>Exploited</dt><dd>{{ coverage.kev.length }}</dd></div>
      <div v-for="k in COUNT_KEYS" :key="k" :class="countTone(k)" :data-test="`coverage-count-${k}`">
        <dt>{{ STATUS_LABEL[k] }}</dt><dd>{{ coverage.counts[k] ?? 0 }}</dd>
      </div>
      <template v-if="coverage.ghsa.length">
        <div><dt>GitHub advisories seen</dt><dd>{{ coverage.counts.ghsa_seen }}</dd></div>
        <div :class="coverage.counts.ghsa_possible ? 'warning' : 'zero'"><dt>Possibly missed</dt><dd>{{ coverage.counts.ghsa_possible }}</dd></div>
      </template>
    </dl>
    <div v-if="coverageGaps.length || coveragePossible.length" class="coverage-gaps">
      <h3>Not warned early <span class="gap-count">{{ coverageGaps.length + coveragePossible.length }}</span></h3>
      <ul class="coverage-list">
        <li v-for="r in coverageGaps" :key="r.cve" class="coverage-row">
          <span :class="['badge', r.status === 'missed' ? 'danger' : 'warning']">{{ STATUS_TEXT[r.status] }}</span>
          <span class="what"><span class="product">{{ kevProduct(r) }}</span> <span class="mono cve">{{ r.cve }}</span></span>
          <span class="when">added {{ r.added }}<template v-if="r.lead_days != null"> · warning {{ days(Math.abs(r.lead_days)) }} {{ r.lead_days >= 0 ? 'before' : 'after' }}</template></span>
        </li>
        <li v-for="a in coveragePossible" :key="a.id" class="coverage-row">
          <span class="badge neutral">possible</span>
          <span class="what"><a class="mono cve" :href="a.url" target="_blank" rel="noopener">{{ a.id }}</a> <span class="product">{{ a.products.join(', ') }}</span> <span class="summary">{{ a.summary }}</span></span>
          <span class="when">published {{ a.published }}</span>
        </li>
      </ul>
    </div>
  </section>

  <section v-if="showConfig" id="ew-config" class="card config">
    <label>
      <span class="field-label">Feeds</span>
      <textarea v-model="feedsText" rows="6" spellcheck="false" placeholder="https://about.gitlab.com/security-releases.xml" />
      <span class="subtext">RSS or Atom, one https URL per line. Only entries from the last 30 days that name one of your products reach the AI provider.</span>
    </label>
    <label>
      <span class="field-label">Products without an agent</span>
      <textarea v-model="productsText" rows="6" spellcheck="false" placeholder="FRITZ!OS | 8.25 | router" />
      <span class="subtext">One per line: name | version | where. Containers, operating systems and network-facing host packages (Tailscale, OpenSSH, Docker, …) come from the agents, TrueNAS and Home Assistant from their connectors.</span>
    </label>
    <div class="research-config">
      <label class="check">
        <input v-model="research.enabled" type="checkbox" :disabled="!data?.ai_configured" />
        <span>Web research</span>
      </label>
      <label class="check">
        <input v-model="research.verify" type="checkbox" :disabled="!data?.ai_configured" />
        <span>Check high hits with the vendor</span>
      </label>
      <span class="subtext"><template v-if="data?.research?.level === 'minimal'">The AI level is Minimal: no web research, and the vendor check uses only the NVD.</template><template v-else>Once every {{ data?.research?.interval_hours ?? 20 }} hours the research model searches the web worldwide for fresh advisories on your products. It catches news no feed has yet; with Sonnet a pass costs about $0.20–0.40.</template> The vendor check compares the facts of every high-severity hit with the vendor’s own advisory<template v-if="data?.research?.level === 'balanced'"> (NVD first, AI only without NVD data)</template> before it is reported. Set the AI level, intervals and models under Settings.</span>
    </div>
    <div class="config-actions">
      <button class="primary" :disabled="saving" @click="saveConfig"><Icon name="check" :size="15" />{{ saving ? 'Saving…' : 'Save' }}</button>
      <button class="secondary" @click="showConfig = false">Close</button>
      <p v-if="configMsg" class="message" :class="configMsg.kind" role="status">{{ configMsg.text }}</p>
    </div>
  </section>

  <section class="card list-card">
    <div class="toolbar">
      <div class="seg" role="tablist" aria-label="Filter by rating">
        <button v-for="[v, l] in FILTERS" :key="v" role="tab" :aria-selected="filter === v"
                :class="['seg-btn', v, { active: filter === v }]" @click="setFilter(v)">
          <i v-if="v" class="dot" />{{ l }}<span v-if="data" class="count">{{ v ? counts[v] || 0 : total }}</span>
        </button>
      </div>
      <span v-if="counts.pending" class="subtext">{{ counts.pending }} queued for the next pass</span>
    </div>

    <p v-if="loading" class="empty">Loading early warnings…</p>
    <ol v-else-if="data?.items?.length" class="ew-list" :class="{ stale: checking }">
      <li v-for="w in data.items" :key="w.id" class="ew">
        <div class="ew-status">
          <span :class="['badge', STATUS[w.status]?.cls || 'neutral']">{{ STATUS[w.status]?.text || w.status }}</span>
          <span v-if="w.severity && w.severity !== 'info' && !done(w)" :class="['badge-sev', w.severity]"
                title="Early warnings are rated at most high; the scanner confirms the rest">{{ label(w.severity) }}</span>
          <span v-if="w.exploited === 'ja'" class="badge danger" title="The advisory says the vulnerability is exploited">Exploited</span>
          <span v-else-if="w.public_exploit === 'yes'" class="badge danger" title="A public exploit or proof of concept exists">Public exploit</span>
        </div>

        <div class="ew-main">
          <a :href="w.link" target="_blank" rel="noopener" class="ew-title">{{ w.title }}<Icon name="external" :size="12" /></a>
          <p v-if="w.summary" class="ew-summary">{{ w.summary }}</p>
          <p class="ew-detail">{{ w.status === 'pending' ? 'Waiting for the next pass (at most 20 entries go to the AI provider per pass).' : w.detail }}</p>
          <ul v-if="w.actions?.length && !done(w)" class="ew-steps" aria-label="Recommended steps">
            <li v-for="(a, i) in steps(w)" :key="i">
              <span class="ew-step-text"><strong>{{ a.system }}</strong> {{ a.text }}</span>
              <span v-if="a.command" class="ew-cmd">
                <code class="mono">{{ a.command }}</code>
                <button class="btn-sm" :aria-label="`Copy command for ${a.system}`" @click="copy(`${w.id}:${i}`, a.command)">
                  <Icon :name="copied === `${w.id}:${i}` ? 'check' : 'copy'" :size="13" />{{ copied === `${w.id}:${i}` ? 'Copied' : 'Copy' }}
                </button>
              </span>
            </li>
          </ul>
          <div v-if="w.mitigations?.length && !done(w)" class="ew-mitigations">
            <span class="field-label">Mitigation from the advisory</span>
            <p v-for="(m, i) in w.mitigations" :key="i">{{ m }}</p>
          </div>
          <div class="ew-meta">
            <time :datetime="w.published" :title="w.published ? fmtDateTime(w.published) : ''">{{ w.published ? fmtDay(w.published) : 'no date' }}</time>
            <span :title="w.origin === 'research' ? 'Found by the web research' : w.feed">{{ w.source }}<template v-if="w.origin === 'research'"> · web research</template></span>
            <span v-if="w.verified" title="Versions and mitigations checked against the vendor's advisory by a web search">checked with vendor</span>
            <span v-if="w.notified_at" :title="fmtDateTime(w.notified_at)">notified {{ timeAgo(w.notified_at) }}</span>
            <span v-else-if="w.duplicate_of" class="truncate" :title="`Same hosts, product and version as an advisory already notified, with no new host, higher severity or newer fix: ${data.items.find(x => x.id === w.duplicate_of)?.title || 'earlier advisory'}`">not notified again, already reported</span>
            <span v-for="m in where(w)" :key="m.product + m.system" class="ew-product" :title="`${m.product} on ${m.system}`">
              <span class="mono truncate">{{ m.product }}</span><span>{{ m.system }}</span>
            </span>
          </div>
          <div v-if="w.cves.length" class="ew-cves">
            <a v-for="c in w.cves" :key="c" :href="`https://nvd.nist.gov/vuln/detail/${c}`" target="_blank" rel="noopener" class="mono">{{ c }}</a>
          </div>
        </div>

        <div class="ew-actions">
          <RouterLink v-if="w.status === 'betroffen'" class="btn-sm" :to="{ path: '/funde', query: { source: 'ai', ...(w.cves[0] && { q: w.cves[0] }) } }">Open finding</RouterLink>
          <button v-if="w.retryable" class="btn-sm" title="The AI provider could not be asked last time; ask again in the next pass" @click="retry(w)">Ask again</button>
        </div>
      </li>
    </ol>
    <p v-else class="empty">{{ data?.ai_configured === false && !filter ? 'Add an AI provider under Settings; until then matched advisories wait for review by hand.' : EMPTY[filter] }}</p>
  </section>
</template>

<style scoped>
.facts { display: flex; flex-wrap: wrap; gap: 0.5rem 1.75rem; padding: 0.75rem 1.25rem; margin-bottom: 1rem; font-size: 0.875rem; color: var(--muted); }
.facts strong { color: var(--text); font-weight: 500; font-variant-numeric: tabular-nums; }
.text-danger { color: var(--crit); }

.coverage { display: flex; flex-direction: column; gap: 1.25rem; }
.coverage-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 0.75rem 1rem; flex-wrap: wrap; }
.coverage-head > div { display: flex; flex-direction: column; gap: 0.25rem; min-width: 0; flex: 1 1 260px; }
.coverage-head h2 { margin: 0; }
.coverage-head p { margin: 0; }
/* Zählerleiste: Zellen auf --ground, die 1px-Lücken zeigen die Linie, auch beim Umbruch */
.coverage-counts {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(9.5rem, 1fr)); gap: 1px; margin: 0;
  background: var(--line); border: 1px solid var(--line); border-radius: var(--radius-sm); overflow: hidden;
}
.coverage-counts > div { display: flex; flex-direction: column; gap: 0.25rem; padding: 0.75rem 1rem; background: var(--ground); }
.coverage-counts dt { display: flex; align-items: center; gap: 0.5rem; font-size: 0.75rem; color: var(--muted); }
.coverage-counts dd { margin: 0; font: 600 1.125rem/1.2 var(--mono); color: var(--text); }
.coverage-counts .total dd { font-size: 1.5rem; }
.coverage-counts .zero dd { color: var(--muted); font-weight: 400; }
.coverage-counts .warning dt::before, .coverage-counts .danger dt::before { content: ''; width: 6px; height: 6px; border-radius: 50%; flex: none; }
.coverage-counts .warning dt::before { background: var(--warn); }
.coverage-counts .danger dt::before { background: var(--danger); }
.coverage-counts .danger dd { color: var(--danger); }
.coverage-gaps { display: flex; flex-direction: column; gap: 0.5rem; }
.coverage-gaps h3 { margin: 0; font-size: 0.6875rem; font-weight: 600; letter-spacing: 0.09em; text-transform: uppercase; color: var(--text-2); }
.gap-count { margin-left: 0.5rem; font: 0.6875rem var(--mono); color: var(--muted); letter-spacing: 0; }
.coverage-list { list-style: none; margin: 0; padding: 0; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--ground); }
.coverage-row {
  display: grid; grid-template-columns: 11.5rem minmax(0, 1fr) auto; align-items: center; gap: 0.25rem 1rem;
  padding: 0.75rem 1rem; border-top: 1px solid var(--line); font-size: 0.875rem;
}
.coverage-row:first-child { border-top: 0; }
.coverage-row .badge { justify-self: start; }
.what { min-width: 0; color: var(--text); overflow-wrap: anywhere; }
.what .cve { margin-left: 0.25rem; font-size: 0.8125rem; color: var(--text-2); }
.what .summary { color: var(--text-2); }
.when { font-size: 0.75rem; color: var(--muted); white-space: nowrap; text-align: right; }
@media (max-width: 640px) {
  .coverage-row { grid-template-columns: minmax(0, 1fr); gap: 0.5rem; }
  .when { white-space: normal; text-align: left; }
}
.notice { display: flex; gap: 0.75rem; align-items: flex-start; padding: 0.75rem 1rem; margin-bottom: 1rem; color: var(--crit); }
.notice div { display: flex; flex-direction: column; gap: 0.125rem; }
.notice strong { color: var(--text); font-weight: 500; }

.config { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 360px), 1fr)); gap: 1rem 1.25rem; }
.config label { display: flex; flex-direction: column; gap: 0.25rem; }
.config textarea { width: 100%; resize: vertical; font-family: var(--mono); font-size: 0.8125rem; line-height: 1.55; }
.config-actions { grid-column: 1 / -1; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
.config-actions .message { margin: 0; }

.list-card { padding-bottom: 0.5rem; }
.toolbar { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; margin-bottom: 0.5rem; }
.seg-btn.betroffen .dot { background: var(--crit); }
.seg-btn.unklar .dot { background: var(--med); }
.seg-btn.behoben .dot,
.seg-btn.nicht_betroffen .dot { background: var(--ok); }

.ew-list { list-style: none; margin: 0; padding: 0; transition: opacity 0.2s; }
.ew-list.stale { opacity: 0.6; }
.ew { display: grid; grid-template-columns: 8.5rem minmax(0, 1fr) auto; gap: 0.25rem 1rem; padding: 1rem 0; border-top: 1px solid var(--line); }
.ew:first-child { border-top: 0; }
.ew-status { display: flex; flex-direction: column; align-items: flex-start; gap: 0.25rem; padding-top: 0.125rem; }
.ew-status .badge { white-space: nowrap; }
.ew-status .badge + .badge { margin-left: 0; }   /* globaler Abstand gilt für Pillen nebeneinander, hier stehen sie untereinander */
.ew-main { display: flex; flex-direction: column; gap: 0.25rem; min-width: 0; }
.ew-title { color: var(--text); font-weight: 500; line-height: 1.4; text-decoration: none; text-wrap: balance; }
.ew-title:hover { text-decoration: underline; text-underline-offset: 3px; }
.ew-title :deep(svg) { margin-left: 0.25rem; vertical-align: -1px; color: var(--muted); }
.ew-detail { margin: 0; font-size: 0.875rem; color: var(--text-2); line-height: 1.5; max-width: 75ch; }
.ew-summary { margin: 0; font-size: 0.875rem; color: var(--text); line-height: 1.5; max-width: 75ch; }
.ew-steps { list-style: none; margin: 0.125rem 0 0; padding: 0; display: flex; flex-direction: column; gap: 0.5rem; max-width: 90ch; }
.ew-steps li { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.8125rem; color: var(--text-2); }
.ew-step-text strong { color: var(--text); font-weight: 500; margin-right: 0.25rem; }
.ew-cmd { display: flex; align-items: center; gap: 0.25rem; min-width: 0; padding: 0.25rem 0.25rem 0.25rem 0.5rem; border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface-2); }
.ew-cmd code { flex: 1; min-width: 0; overflow-x: auto; white-space: nowrap; font-size: 0.75rem; color: var(--text); }
.ew-mitigations { display: flex; flex-direction: column; gap: 0.125rem; max-width: 80ch; padding-left: 0.75rem; border-left: 2px solid var(--line-strong); }
.ew-mitigations p { margin: 0; font-size: 0.8125rem; color: var(--text-2); line-height: 1.5; }
.research-config { grid-column: 1 / -1; display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 1rem; }
.research-config .check { display: inline-flex; align-items: center; gap: 0.5rem; font-size: 0.875rem; }
.research-config .subtext { flex-basis: 100%; }
.ew-meta { display: flex; flex-wrap: wrap; align-items: center; gap: 0.25rem 1rem; font-size: 0.75rem; color: var(--muted); }
.ew-meta time { font-variant-numeric: tabular-nums; }
.ew-product { display: inline-flex; align-items: center; gap: 0.5rem; max-width: 100%; padding: 0.125rem 0.5rem; border: 1px solid var(--line); border-radius: 6px; background: var(--surface-2); }
.ew-product .mono { font-size: 0.75rem; color: var(--text-2); max-width: 28ch; }
.ew-cves { display: flex; flex-wrap: wrap; gap: 0.25rem 0.75rem; font-size: 0.75rem; }
.ew-cves a { color: var(--text-2); text-decoration: none; }
.ew-cves a:hover { color: var(--text); text-decoration: underline; text-underline-offset: 3px; }
.ew-actions { display: flex; flex-direction: column; align-items: flex-end; gap: 0.5rem; }
.ew-actions .btn-sm { white-space: nowrap; text-decoration: none; }
/* Navigation bleibt ein Link, sieht aber aus wie die Schaltflächen daneben */
.ew-actions a.btn-sm {
  display: inline-flex; align-items: center; font-weight: 500; color: var(--text); background: var(--surface-2);
  border: 1px solid var(--line-strong); border-radius: var(--radius-sm); transition: background-color 0.15s, border-color 0.15s;
}
.ew-actions a.btn-sm:hover { background: var(--surface-3); border-color: #3d4048; }
.ew-actions a.btn-sm:focus-visible { outline: 2px solid var(--text-2); outline-offset: 2px; }

.spin { animation: spin 0.9s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spin { animation: none; } }

@media (max-width: 720px) {
  .ew { grid-template-columns: minmax(0, 1fr); }
  .ew-status { flex-direction: row; }
  .ew-actions { flex-direction: row; align-items: flex-start; }
}
</style>
