<script setup>
import { computed, reactive, ref } from 'vue'
import { api } from '../api.js'
import { KINDS, PRESETS, fmtMs, newCheck } from '../health.js'
import Icon from './Icon.vue'
import ToggleSwitch from './ToggleSwitch.vue'

// Konfigurationsgenerator: Host, Prüfungen mit allen Einstellungen, Test vor dem Speichern.
// Bei Agenten-Hosts sind Name und Agentenprüfung fest; alles andere lässt sich ergänzen.
const props = defineProps({
  monitor: { type: Object, default: null },
  options: { type: Object, required: true },
})
const emit = defineEmits(['saved', 'cancel'])

const auto = computed(() => !!props.monitor?.auto)
const form = reactive({
  name: props.monitor?.name || '',
  host: props.monitor?.host || '',
  slug: props.monitor?.slug || '',
  critical: props.monitor?.critical ?? true,
  paused: props.monitor?.paused ?? false,
  checks: (props.monitor?.checks || [newCheck('ping')]).map((c) => ({
    id: c.id, kind: c.kind, params: { ...KINDS[c.kind]?.defaults, ...c.params }, interval_s: c.interval_s ?? 30,
    retry_s: c.retry_s ?? 10, timeout_s: c.timeout_s ?? 5, fails_degraded: c.fails_degraded ?? 2, fails_down: c.fails_down ?? 4,
    paused: c.paused ?? false, auth: null, has_auth: c.has_auth, heartbeat: c.heartbeat,
  })),
})
const available = computed(() => Object.fromEntries((props.options?.kinds || []).map((k) => [k.kind, k])))
const addKind = ref('')
const busy = ref(false)
const error = ref('')
const tests = reactive({})
const beatTokens = ref(null)

function add(kind, params = {}) {
  form.checks.push(newCheck(kind, params))
  addKind.value = ''
}
function remove(i) {
  form.checks.splice(i, 1)
}
function onScheme(c) {
  if ([80, 443].includes(Number(c.params.port))) c.params.port = c.params.scheme === 'https' ? 443 : 80
}

function payload() {
  return {
    name: form.name.trim(), host: form.host.trim(), slug: form.slug.trim() || null, critical: form.critical, paused: form.paused,
    checks: form.checks.map((c) => ({
      id: c.id ?? null, kind: c.kind, params: c.params, interval_s: Number(c.interval_s), retry_s: Number(c.retry_s),
      timeout_s: Number(c.timeout_s), fails_degraded: Number(c.fails_degraded), fails_down: Number(c.fails_down), paused: c.paused,
      auth: c.auth,
    })),
  }
}

async function test(c, i) {
  tests[i] = { busy: true }
  try {
    const r = await api.post('/api/health/test', { host: form.host.trim(), check: payload().checks[i] })
    tests[i] = r
  } catch (e) {
    tests[i] = { ok: false, error: e.message }
  }
}

async function save() {
  busy.value = true
  error.value = ''
  try {
    const body = payload()
    const r = props.monitor
      ? await api.put(`/api/health/monitors/${props.monitor.id}`, body)
      : await api.post('/api/health/monitors', body)
    if (Object.keys(r.heartbeat_tokens || {}).length) beatTokens.value = r.heartbeat_tokens
    else emit('saved', r)
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}
const beatUrl = (t) => `${window.location.origin}/api/health/beat/${t}`
</script>

<template>
  <form class="monitor-form" @submit.prevent="save">
    <template v-if="!beatTokens">
      <h2>{{ monitor ? `Edit ${monitor.name}` : 'Add a host' }}</h2>
      <div class="grid-2">
        <label>Name
          <input v-model="form.name" required maxlength="80" :disabled="auto" placeholder="e.g. TrueNAS" />
          <span v-if="auto" class="hint">Hosts from Systems carry the name of their system.</span>
        </label>
        <label>Host (IP or name)
          <input v-model="form.host" maxlength="253" placeholder="REDACTED" spellcheck="false" />
          <span class="hint">Target of all checks without their own target.</span>
        </label>
      </div>
      <div class="flags">
        <span class="toggle-row"><ToggleSwitch v-model="form.critical" label="Critical: alert when it goes down" /><span aria-hidden="true">Critical: alert when it goes down</span></span>
        <span class="toggle-row"><ToggleSwitch v-model="form.paused" label="Paused" /><span aria-hidden="true">Paused</span></span>
      </div>
      <details class="advanced">
        <summary>API key</summary>
        <label>Key in the API (letters, digits, dashes)
          <input v-model="form.slug" maxlength="40" pattern="[a-z0-9][a-z0-9\-]*" placeholder="generated from the name" spellcheck="false" />
          <span class="hint">Devices reading <code>/api/health/states</code> use this key. Changing it breaks their configuration.</span>
        </label>
      </details>

      <h3>Checks</h3>
      <ol class="checks">
        <li v-for="(c, i) in form.checks" :key="c.id ?? `new-${i}`" class="check">
          <header>
            <div>
              <strong>{{ KINDS[c.kind].label }}</strong>
              <span class="hint">{{ KINDS[c.kind].hint }}</span>
            </div>
            <div class="check-actions">
              <button v-if="!['agent', 'heartbeat'].includes(c.kind)" type="button" class="btn-sm" :disabled="tests[i]?.busy" @click="test(c, i)">
                <Icon name="play" :size="13" />Test
              </button>
              <button v-if="c.kind !== 'agent'" type="button" class="btn-sm btn-delete" :aria-label="`Remove ${KINDS[c.kind].label}`" @click="remove(i)"><Icon name="trash" :size="13" /></button>
            </div>
          </header>

          <div class="fields">
            <label v-if="KINDS[c.kind].fields.includes('target')">Own target <input v-model="c.params.target" placeholder="host above" spellcheck="false" /></label>
            <label v-if="KINDS[c.kind].fields.includes('fritz_target')">Device (MAC or IP) <input v-model="c.params.target" placeholder="REDACTED" spellcheck="false" /></label>
            <label v-if="KINDS[c.kind].fields.includes('scheme')">Scheme
              <select v-model="c.params.scheme" @change="onScheme(c)"><option value="http">http</option><option value="https">https</option></select>
            </label>
            <label v-if="KINDS[c.kind].fields.includes('port')">Port <input v-model.number="c.params.port" type="number" min="1" max="65535" /></label>
            <label v-if="KINDS[c.kind].fields.includes('path')">Path <input v-model="c.params.path" placeholder="/" spellcheck="false" /></label>
            <label v-if="KINDS[c.kind].fields.includes('method')">Method
              <select v-model="c.params.method"><option>GET</option><option>HEAD</option></select>
            </label>
            <label v-if="KINDS[c.kind].fields.includes('expect')">Expected status <input v-model="c.params.expect" placeholder="2xx, 200,301 or 200-399" spellcheck="false" /></label>
            <label v-if="KINDS[c.kind].fields.includes('match')" class="wide">Response must contain (optional) <input v-model="c.params.match" maxlength="200" /></label>
            <label v-if="KINDS[c.kind].fields.includes('auth')" class="wide">Authorization header (optional)
              <input v-model="c.auth" type="password" autocomplete="off" :placeholder="c.has_auth ? 'stored – leave empty to keep' : 'Bearer … or Basic …'" />
              <span class="hint">Stored encrypted, never shown again.<button v-if="c.has_auth" type="button" class="link" @click="c.auth = ''">Remove stored header</button></span>
            </label>
            <label v-if="KINDS[c.kind].fields.includes('server_name')">Server name (SNI) <input v-model="c.params.server_name" placeholder="host above" spellcheck="false" /></label>
            <label v-if="KINDS[c.kind].fields.includes('warn_days')">Warn days before expiry <input v-model.number="c.params.warn_days" type="number" min="0" max="365" /></label>
            <label v-if="KINDS[c.kind].fields.includes('name')">Query name <input v-model="c.params.name" spellcheck="false" /></label>
            <label v-if="KINDS[c.kind].fields.includes('rtype')">Record
              <select v-model="c.params.rtype"><option>A</option><option>AAAA</option></select>
            </label>
            <label v-if="KINDS[c.kind].fields.includes('grace_s')">Grace (s) <input v-model.number="c.params.grace_s" type="number" min="0" /></label>
          </div>
          <div v-if="KINDS[c.kind].fields.includes('verify_tls')" class="flags">
            <span class="toggle-row"><ToggleSwitch v-model="c.params.verify_tls" label="Verify certificate" /><span aria-hidden="true">Verify certificate</span></span>
            <span class="toggle-row"><ToggleSwitch v-model="c.params.follow_redirects" label="Follow redirects" /><span aria-hidden="true">Follow redirects</span></span>
          </div>
          <p v-if="c.kind === 'heartbeat' && c.heartbeat" class="hint">The heartbeat address was shown when it was created; a new one can be made in the list.</p>

          <details class="advanced">
            <summary>Timing and thresholds</summary>
            <div class="fields">
              <label>{{ c.kind === 'heartbeat' ? 'Expected every (s)' : 'Every (s)' }} <input v-model.number="c.interval_s" type="number" min="10" max="3600" /></label>
              <label v-if="c.kind !== 'heartbeat'">After a failure every (s) <input v-model.number="c.retry_s" type="number" min="5" max="3600" /></label>
              <label v-if="!['agent', 'heartbeat'].includes(c.kind)">Timeout (s) <input v-model.number="c.timeout_s" type="number" min="1" max="30" step="0.5" /></label>
              <label>Failures until degraded <input v-model.number="c.fails_degraded" type="number" min="1" max="20" /></label>
              <label>Failures until down <input v-model.number="c.fails_down" type="number" min="1" max="50" /></label>
            </div>
            <span class="toggle-row"><ToggleSwitch v-model="c.paused" label="Pause this check" /><span aria-hidden="true">Pause this check</span></span>
          </details>

          <p v-if="tests[i] && !tests[i].busy" :class="['test', tests[i].ok ? (tests[i].warn ? 'warning' : 'ok') : 'error']" role="status">
            <Icon :name="tests[i].ok ? 'check' : 'x'" :size="14" />
            <span v-if="tests[i].ok">Reachable · {{ fmtMs(tests[i].latency_ms) }}<template v-if="tests[i].warn"> · {{ tests[i].warn }}</template></span>
            <span v-else>{{ tests[i].inconclusive ? 'Not decidable: ' : 'Failed: ' }}{{ tests[i].error }}</span>
          </p>
        </li>
      </ol>

      <div class="add">
        <div class="presets" role="group" aria-label="Quick add">
          <button v-for="p in PRESETS" :key="p.label" type="button" class="chip" @click="add(p.kind, p.params)"><Icon name="plus" :size="12" />{{ p.label }}</button>
        </div>
        <label class="add-kind">Add check
          <select v-model="addKind" @change="addKind && add(addKind)">
            <option value="" disabled>Choose a check type …</option>
            <option v-for="(k, key) in KINDS" :key="key" :value="key" :disabled="!available[key]?.available">
              {{ k.label }}{{ available[key] && !available[key].available ? ` – ${available[key].reason}` : '' }}
            </option>
          </select>
        </label>
        <p v-if="!options.fritz" class="hint">
          FRITZ!Box checks (device active, internet) need the FRITZ!Box connector.
          <RouterLink to="/einstellungen?tab=exposure#set-fritz">Set it up under Settings → Exposure</RouterLink>; its user needs the right “FRITZ!Box settings”.
        </p>
      </div>

      <p v-if="error" class="message error" role="alert">{{ error }}</p>
      <div class="modal-actions">
        <button type="button" class="secondary" @click="emit('cancel')">Cancel</button>
        <button type="submit" class="primary" :disabled="busy || !form.checks.length">{{ monitor ? 'Save' : 'Add host' }}</button>
      </div>
    </template>

    <template v-else>
      <h2>Heartbeat addresses</h2>
      <p class="hint">Shown only now. Let the device call this address at least every interval, e.g. from cron or a shutdown hook:</p>
      <div v-for="(t, id) in beatTokens" :key="id" class="cmd-block">
        <pre class="cmd-text">curl -fsS {{ beatUrl(t) }}
# on shutdown: turns the host red right away
curl -fsS "{{ beatUrl(t) }}?state=down"</pre>
      </div>
      <div class="modal-actions"><button type="button" class="primary" @click="emit('saved', {})">Done</button></div>
    </template>
  </form>
</template>

<style scoped>
.monitor-form { display: flex; flex-direction: column; gap: 1rem; }
h2 { margin: 0; font-size: 1.125rem; }
h3 { margin: 0.5rem 0 0; font-size: 0.6875rem; font-weight: 600; letter-spacing: 0.09em; text-transform: uppercase; color: var(--text-2); }
.grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }
.flags { display: flex; gap: 0.75rem 1.75rem; flex-wrap: wrap; }
.toggle-row { display: inline-flex; align-items: center; gap: 0.5rem; font-size: 0.8125rem; color: var(--text-2); }
.hint { font-size: 0.75rem; color: var(--muted); }
.hint code { font-size: 0.75rem; }
.advanced summary { cursor: pointer; font-size: 0.8125rem; color: var(--text-2); }
.advanced[open] { display: flex; flex-direction: column; gap: 0.75rem; }
.checks { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.75rem; }
.check { display: flex; flex-direction: column; gap: 0.75rem; padding: 1rem; border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--ground); }
.check header { display: flex; justify-content: space-between; gap: 0.75rem; align-items: flex-start; }
.check header > div:first-child { display: flex; flex-direction: column; gap: 0.125rem; }
.check-actions { display: flex; gap: 0.5rem; }
.fields { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 0.75rem; }
.fields .wide { grid-column: 1 / -1; }
.fields .hint { display: flex; gap: 0.5rem; flex-wrap: wrap; }
.test { display: flex; gap: 0.5rem; align-items: center; margin: 0; font-size: 0.8125rem; }
.test.ok { color: var(--ok); }
.test.warning { color: var(--warn); }
.test.error { color: var(--danger); }
.add { display: flex; flex-direction: column; gap: 0.75rem; }
.presets { display: flex; gap: 0.5rem; flex-wrap: wrap; }
.chip { min-height: 28px; padding: 0.125rem 0.5rem; font-size: 0.75rem; border-radius: var(--radius-pill); gap: 0.25rem; }
.add-kind { max-width: 420px; }
.modal-actions { display: flex; justify-content: flex-end; gap: 0.5rem; }
.cmd-block { border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--ground); overflow: hidden; }
.cmd-text { margin: 0; padding: 0.75rem; overflow: auto; font: 0.75rem/1.55 var(--mono); color: var(--text-2); white-space: pre; }
</style>
