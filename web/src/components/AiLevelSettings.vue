<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import { ASSUMED_NVD_SHARE, DEFAULT_RESEARCH_HOURS, LEVELS, SWITCHES, VERIFY_DEFAULTS, VERIFY_REPEAT, estimate, fmtUsd } from '../aicost.js'
import Icon from './Icon.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsFold from './SettingsFold.vue'
import SettingsList from './SettingsList.vue'
import SettingsSection from './SettingsSection.vue'
import ToggleSwitch from './ToggleSwitch.vue'

const KEYS = ['level', 'pass_hours', 'research_hours', 'max_searches', ...Object.keys(VERIFY_DEFAULTS), ...SWITCHES.map((x) => x.id)]
const cfg = reactive({ level: 'full', pass_hours: 2, research_hours: 20, max_searches: 15, ...VERIFY_DEFAULTS, kev: true, release_feeds: true, health_alerts: true, miss_check: true })
const releaseFeeds = ref([])
const saved = ref(null)
const basis = ref(null)
const research = ref({ enabled: true, verify: true })
const busy = ref(false)
const message = ref(null)
const loadError = ref(null)

async function load() {
  loadError.value = null
  try {
    const data = await api.get('/api/early-warnings/ai-level')
    for (const k of KEYS) if (data[k] !== undefined) cfg[k] = data[k]   // ein älterer Server kennt nicht jeden Wert
    releaseFeeds.value = data.release_feeds_found || []
    saved.value = { ...cfg }
    basis.value = data.basis
    research.value = data.research
  } catch (e) {
    loadError.value = e.message
  }
}
onMounted(load)

function pick(level) {
  if (level === cfg.level) return
  cfg.level = level
  cfg.research_hours = DEFAULT_RESEARCH_HOURS[level]
}

// Andere Stufen mit ihrem vorgeschlagenen Recherche-Abstand, die gewählte mit den eingegebenen Werten
const perLevel = computed(() => {
  if (!basis.value) return {}
  return Object.fromEntries(LEVELS.map((l) => [l.id, estimate(basis.value, l.id === cfg.level ? cfg
    : { ...cfg, level: l.id, research_hours: DEFAULT_RESEARCH_HOURS[l.id] }, research.value)]))
})
const current = computed(() => perLevel.value[cfg.level])
const valid = computed(() => Number.isInteger(cfg.pass_hours) && cfg.pass_hours >= 1 && cfg.pass_hours <= 24
  && Number.isInteger(cfg.research_hours) && cfg.research_hours >= 6 && cfg.research_hours <= 336
  && Number.isInteger(cfg.max_searches) && cfg.max_searches >= 5 && cfg.max_searches <= 30
  && [cfg.verify_searches, cfg.verify_per_pass].every((n) => Number.isInteger(n) && n >= 1 && n <= 10))
const repeat = computed(() => VERIFY_REPEAT.find((r) => r.id === cfg.verify_repeat) || VERIFY_REPEAT[0])
const dirty = computed(() => !!saved.value && KEYS.some((k) => cfg[k] !== saved.value[k]))
const status = computed(() => ({ tone: 'neutral', text: LEVELS.find((l) => l.id === (saved.value?.level || 'full')).label }))
const ICONS = { kev: 'shield', release_feeds: 'package', health_alerts: 'bell', miss_check: 'activity' }

const assumptions = computed(() => {
  const b = basis.value
  if (!b) return []
  const out = [`Frequencies measured over the last ${b.days} days; token use measured from ${b.classify.measured} reads, ${b.research.measured} research runs and ${b.verify.measured} AI checks (assumed until measured).`]
  out.push(b.verify.nvd_share == null
    ? `Share of checks the NVD can answer: ${ASSUMED_NVD_SHARE * 100} % assumed until measured (early reports rarely have an analysed CVE yet).`
    : `The NVD answered ${Math.round(b.verify.nvd_share * 100)} % of ${b.verify.nvd_measured} checks.`)
  out.push(`Anthropic list prices; web search $${(b.search_usd * 1000).toFixed(0)} per 1,000 searches. No price is known for other providers; local models cost nothing.`)
  if (cfg.kev || cfg.release_feeds) out.push('KEV and release feeds add a few reads per month with the cheap model (cents).')
  if (!research.value.enabled) out.push('Web research is switched off on the Early warnings page.')
  if (!research.value.verify) out.push('The vendor check is switched off on the Early warnings page.')
  return out
})

async function save() {
  busy.value = true
  message.value = null
  try {
    await api.put('/api/early-warnings/ai-level', { ...cfg })
    saved.value = { ...cfg }
    message.value = { kind: 'ok', text: 'Saved. The next early warning pass uses it.' }
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <SettingsCard icon="sparkles" title="AI level and cost" subtitle="How much of the early warning runs on AI, how often, and what it costs" :status="status">
    <template #intro>
      Fully agentic uses AI and web search for every step. The lower levels use structured public data (NVD, CISA KEV) instead:
      fewer AI calls and lower cost, but less news coverage.
    </template>
    <p v-if="loadError" class="message error" role="alert">{{ loadError }}
      <button type="button" class="btn-sm" @click="load"><Icon name="refresh" :size="14" />Retry</button>
    </p>

    <div id="set-ai-level" class="levels" role="radiogroup" aria-label="AI level">
      <button v-for="l in LEVELS" :key="l.id" type="button" role="radio" :aria-checked="cfg.level === l.id"
              :class="['level', { active: cfg.level === l.id }]" :data-test="`level-${l.id}`" @click="pick(l.id)">
        <span class="level-head">
          <strong>{{ l.label }}</strong>
          <span class="level-cost" :data-test="`cost-${l.id}`">{{ fmtUsd(perLevel[l.id]?.total) }}<small>/month</small></span>
        </span>
        <span class="level-text">{{ l.text }}</span>
      </button>
    </div>

    <SettingsSection id="set-ai-sources" title="Sources and safety nets">
      <SettingsList label="Sources and safety nets">
        <SettingsEntry v-for="x in SWITCHES" :key="x.id" :icon="ICONS[x.id]" :title="x.label" :meta="x.text">
          <template #actions>
            <ToggleSwitch v-model="cfg[x.id]" :name="`switch_${x.id}`" :label="x.label" :data-test="`switch-${x.id}`" />
          </template>
          <SettingsFold v-if="x.id === 'release_feeds' && cfg.release_feeds" data-test="release-feeds"
                        :title="`${releaseFeeds.length} release feeds found in your inventory`">
            <ul class="feeds">
              <li v-for="f in releaseFeeds" :key="f.url"><a :href="f.url.replace(/\/releases\.atom$/, '/releases')" target="_blank" rel="noopener">{{ f.url.replace('https://github.com/', '').replace('/releases.atom', '') }}</a> <span class="subtext">{{ f.keywords.join(', ') }}</span></li>
            </ul>
            <span class="subtext">From the images’ <code>org.opencontainers.image.source</code> label, only when the repository name matches the product (a label inherited from a base image does not count).</span>
          </SettingsFold>
        </SettingsEntry>
      </SettingsList>
    </SettingsSection>

    <SettingsFold id="set-ai-tune" title="Fine-tune intervals"
                  :hint="`feeds every ${cfg.pass_hours} h${cfg.level === 'minimal' ? '' : ` · research every ${cfg.research_hours} h · ${cfg.max_searches} searches`}`">
      <div class="intervals">
        <label>
          <span class="field-label">Check feeds every (hours)</span>
          <input v-model.number="cfg.pass_hours" type="number" min="1" max="24" step="1" data-test="pass-hours" />
        </label>
        <label>
          <span class="field-label">Web research every (hours)</span>
          <input v-model.number="cfg.research_hours" type="number" min="6" max="336" step="1" data-test="research-hours"
                 :disabled="cfg.level === 'minimal'" />
        </label>
        <label>
          <span class="field-label">Searches per research run</span>
          <input v-model.number="cfg.max_searches" type="number" min="5" max="30" step="1" data-test="max-searches"
                 :disabled="cfg.level === 'minimal'" />
        </label>
      </div>
      <span class="subtext">Feed checks cost little: AI only reads new matched advisories. Web research is the expensive part and runs at the first feed check after its interval.
        Each search costs $0.01 plus the pages the model reads; fewer searches cover fewer of your products per run.</span>
    </SettingsFold>

    <SettingsFold id="set-ai-verify" title="Vendor check"
                  :hint="cfg.level === 'minimal' ? `${repeat.label.toLowerCase()} · NVD only` : `${repeat.label.toLowerCase()} · ${cfg.verify_searches} searches · up to ${cfg.verify_per_pass} per pass`">
      <div class="intervals">
        <label>
          <span class="field-label">Check a product version again</span>
          <select v-model="cfg.verify_repeat" name="verify_repeat" data-test="verify-repeat">
            <option v-for="r in VERIFY_REPEAT" :key="r.id" :value="r.id">{{ r.label }}</option>
          </select>
        </label>
        <label>
          <span class="field-label">Searches per vendor check</span>
          <input v-model.number="cfg.verify_searches" type="number" min="1" max="10" step="1" data-test="verify-searches"
                 :disabled="cfg.level === 'minimal'" />
        </label>
        <label>
          <span class="field-label">Vendor checks per feed check (at most)</span>
          <input v-model.number="cfg.verify_per_pass" type="number" min="1" max="10" step="1" data-test="verify-per-pass" />
        </label>
      </div>
      <span class="subtext">{{ repeat.text }} The vendor check looks up the vendor’s advisory for every critical or high match before it alerts, and is usually the largest part of the cost.
        The model for it is chosen under <a href="#set-ai-models">Models per task</a>.</span>
    </SettingsFold>

    <SettingsFold v-if="current" id="set-ai-cost" title="Cost estimate" :hint="`${fmtUsd(current.total)} per month`">
      <div class="table-wrap">
      <table class="cost-table" data-test="breakdown">
        <thead><tr><th>Task</th><th>Model</th><th class="num">Runs</th><th class="num">Each</th><th class="num">Month</th></tr></thead>
        <tbody>
          <tr v-for="r in current.rows" :key="r.task">
            <td>{{ r.label }}</td>
            <td class="model">{{ r.count === 0 ? '—' : r.model || 'no model' }}</td>
            <td class="num">{{ Math.round(r.count) }} {{ r.unit }}</td>
            <td class="num">{{ r.count === 0 ? '—' : fmtUsd(r.usd) }}</td>
            <td class="num">{{ fmtUsd(r.total) }}</td>
          </tr>
        </tbody>
      </table>
      </div>
      <ul class="assumptions subtext">
        <li v-for="a in assumptions" :key="a">{{ a }}</li>
      </ul>
    </SettingsFold>

    <div class="actions">
      <button type="button" class="primary" data-test="save-level" :disabled="busy || !valid || !dirty" @click="save"><Icon name="check" :size="15" />Save</button>
    </div>
    <p v-if="!valid" class="message error" role="alert">Feed checks: 1–24 hours. Web research: 6–336 hours, 5–30 searches. Vendor check: 1–10 searches, 1–10 per feed check.</p>
    <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
  </SettingsCard>
</template>

<style scoped>
.levels { display: grid; gap: 0.5rem; grid-template-columns: repeat(auto-fit, minmax(min(100%, 220px), 1fr)); }
/* Globale Buttons zentrieren ihren Inhalt; die Stufen-Karten lesen sich links ausgerichtet */
.level { display: flex; flex-direction: column; align-items: stretch; justify-content: flex-start; gap: 0.25rem; text-align: left;
         padding: 0.75rem; border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--surface-2); color: var(--text-2); }
.level:hover:not(:disabled) { background: var(--surface-3); }
.level.active, .level.active:hover:not(:disabled) { border-color: var(--text-2); background: var(--surface); color: var(--text); box-shadow: inset 0 0 0 1px var(--text-2); }
.level-head { display: flex; justify-content: space-between; align-items: baseline; gap: 0.5rem; }
.level-head strong { color: var(--text); }
.level-cost { font-variant-numeric: tabular-nums; font-weight: 600; color: var(--text); }
.level-cost small { font-weight: 400; color: var(--text-2); margin-left: 0.125rem; }
.level-text { font-size: 0.8125rem; line-height: 1.4; font-weight: 400; }
.intervals { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(min(100%, 200px), 1fr)); max-width: 48rem; }
.table-wrap { overflow-x: auto; margin: 0; padding: 0; }
.cost-table { width: 100%; border-collapse: collapse; font-size: 0.8125rem; }
.cost-table th, .cost-table td { padding: 0.5rem; border-bottom: 1px solid var(--line); text-align: left; }
.cost-table th { color: var(--text-2); font-weight: 500; }
.cost-table .num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.cost-table .model { color: var(--text-2); overflow-wrap: anywhere; }
.feeds { margin: 0; padding-left: 1rem; font-size: 0.8125rem; overflow-wrap: anywhere; }
.assumptions { margin: 0; padding-left: 1rem; display: flex; flex-direction: column; gap: 0.25rem; }
</style>
