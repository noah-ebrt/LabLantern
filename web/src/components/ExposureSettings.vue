<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import { useLive } from '../live.js'
import { fmtStamp, timeAgo } from '../time.js'
import Icon from './Icon.vue'
import RouterForwardsSettings from './RouterForwardsSettings.vue'
import SecretField from './SecretField.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import SettingsFold from './SettingsFold.vue'

// Internet-Erreichbarkeit aus Nginx Proxy Manager, FRITZ!Box, Cloudflare Tunnel und Traefik-Labels.
// Jede Quelle ist eine Zeile; das Verbindungsformular liegt eingeklappt darunter.
const npm = ref(null)
const fritz = ref(null)
const cf = ref(null)
const traefik = ref(null)
const cform = reactive({ account_id: '', token: '' })
const fform = reactive({ url: '', user: '', password: '' })
const systems = ref([])
const form = reactive({ url: '', email: '', password: '', system_id: null })
const message = ref(null)
const busy = ref(false)

async function load() {
  const [n, s, f, c] = await Promise.all([api.get('/api/settings/npm'), api.get('/api/systems'),
    api.get('/api/settings/fritzbox'), api.get('/api/settings/cftunnel')])
  cf.value = c
  traefik.value = (await api.get('/api/settings/traefik').catch(() => null))?.state || null
  if (c.config && !cform.account_id) cform.account_id = c.config.account_id
  npm.value = n
  fritz.value = f
  if (f.config && !fform.url) Object.assign(fform, { url: f.config.url, user: f.config.user })
  systems.value = s.filter((x) => x.status === 'active')
  if (n.config && !form.url) Object.assign(form, { url: n.config.url, email: n.config.email, system_id: n.config.system_id })
}

async function saveNpm() {
  busy.value = true
  message.value = null
  try {
    await api.put('/api/settings/npm', { url: form.url, email: form.email, password: form.password || null, system_id: form.system_id })
    form.password = ''
    const r = await api.post('/api/settings/npm/test')
    message.value = r.ok
      ? { kind: 'ok', text: `Connected: ${r.hosts} proxy hosts, ${Object.values(r.exposed).flat().length} containers marked internet-exposed.` }
      : { kind: 'error', text: `Saved, but NPM could not be read: ${r.error}` }
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

const marked = computed(() => Object.entries(npm.value?.overrides?.hosts || {}))

async function setMark(names, mark) {
  const hosts = { ...(npm.value?.overrides?.hosts || {}) }
  for (const n of names) {
    if (mark) hosts[n.toLowerCase()] = mark
    else delete hosts[n.toLowerCase()]
  }
  busy.value = true
  try {
    await api.put('/api/settings/exposure-overrides', { hosts, entrypoints: npm.value?.overrides?.entrypoints || {} })
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
    busy.value = false
    return
  }
  busy.value = false
  await testNpm()   // gilt erst nach dem nächsten Abgleich: gleich neu lesen
}

async function setEntrypoint(name, mark) {
  const entrypoints = { ...(npm.value?.overrides?.entrypoints || {}) }
  if (mark) entrypoints[name] = mark
  else delete entrypoints[name]
  busy.value = true
  try {
    await api.put('/api/settings/exposure-overrides', { hosts: npm.value?.overrides?.hosts || {}, entrypoints })
    message.value = { kind: 'ok', text: `Entrypoint ${name} saved; applies with the next scan or version check.` }
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

async function testNpm() {
  busy.value = true
  message.value = null
  try {
    const r = await api.post('/api/settings/npm/test')
    message.value = r.ok ? { kind: 'ok', text: `Connected: ${r.hosts} proxy hosts, ${(r.certificates || []).length} certificates in use.` }
      : { kind: 'error', text: `NPM could not be read: ${r.error}` }
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

const fritzText = (r) => `${r.forwards} port forwards, ${Object.values(r.exposed).flat().length} containers or hosts internet-exposed`

async function saveFritz() {
  busy.value = true
  message.value = null
  try {
    await api.put('/api/settings/fritzbox', { url: fform.url, user: fform.user, password: fform.password || null })
    fform.password = ''
    const r = await api.post('/api/settings/fritzbox/test')
    message.value = r.ok ? { kind: 'ok', text: `Connected: ${fritzText(r)}.` }
      : { kind: 'error', text: `Saved, but the FRITZ!Box could not be read: ${r.error}` }
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

async function testFritz() {
  busy.value = true
  message.value = null
  try {
    const r = await api.post('/api/settings/fritzbox/test')
    message.value = r.ok ? { kind: 'ok', text: `Connected: ${fritzText(r)}.` } : { kind: 'error', text: `FRITZ!Box could not be read: ${r.error}` }
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

async function removeFritz() {
  if (!confirm('Remove the FRITZ!Box connection? Containers marked by hand stay marked.')) return
  await api.del('/api/settings/fritzbox')
  Object.assign(fform, { url: '', user: '', password: '' })
  await load()
}

const cfText = (r) => `${r.tunnels} tunnels, ${Object.values(r.exposed).flat().length} containers or hosts internet-exposed`

async function saveCf() {
  busy.value = true
  message.value = null
  try {
    await api.put('/api/settings/cftunnel', { account_id: cform.account_id, token: cform.token || null })
    cform.token = ''
    const r = await api.post('/api/settings/cftunnel/test')
    message.value = r.ok ? { kind: 'ok', text: `Connected: ${cfText(r)}.` }
      : { kind: 'error', text: `Saved, but Cloudflare could not be read: ${r.error}` }
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

async function testCf() {
  busy.value = true
  message.value = null
  try {
    const r = await api.post('/api/settings/cftunnel/test')
    message.value = r.ok ? { kind: 'ok', text: `Connected: ${cfText(r)}.` } : { kind: 'error', text: `Cloudflare could not be read: ${r.error}` }
    await load()
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

async function removeCf() {
  if (!confirm('Remove the Cloudflare Tunnel connection? Containers marked by hand stay marked.')) return
  await api.del('/api/settings/cftunnel')
  Object.assign(cform, { account_id: '', token: '' })
  await load()
}

const exposedCount = computed(() => Object.values(npm.value?.state?.exposed || {}).flat().length)

// Zustand einer Quelle für Badge und Kartenstatus
const sourceState = (cfg, st) => (!cfg ? { tone: 'neutral', text: 'Not connected' } : !st?.configured ? { tone: 'neutral', text: 'Not read yet' }
  : st.ok ? { tone: 'ok', text: 'Connected' } : { tone: 'danger', text: 'Failing' })
const lastRead = (st, text) => (!st?.configured ? 'Not read yet'
  : st.ok ? `Last read ${timeAgo(new Date(st.at * 1000).toISOString())}: ${text()}` : `Last read failed: ${st.error}`)

const status = computed(() => {
  const states = [[npm.value?.config, npm.value?.state], [fritz.value?.config, fritz.value?.state], [cf.value?.config, cf.value?.state]]
    .map(([c, s]) => sourceState(c, s))
  const failing = states.filter((s) => s.tone === 'danger').length
  const connected = states.filter((s) => s.text !== 'Not connected').length
  if (failing) return { tone: 'danger', text: `${failing} failing`, target: ['set-npm', 'set-fritz', 'set-cf'][states.findIndex((s) => s.tone === 'danger')] }
  if (!connected) return { tone: 'neutral', text: traefik.value?.configured ? 'Traefik only' : 'Not connected' }
  return { tone: 'ok', text: `${connected} of 3 connected${traefik.value?.configured ? ' · Traefik' : ''}` }
})

const certs = computed(() => npm.value?.state?.certificates || [])
const nextExpiry = computed(() => Math.min(...certs.value.map((c) => c.days_left ?? -1)))

async function removeNpm() {
  if (!confirm('Remove the NPM connection? Containers marked by hand stay marked.')) return
  await api.del('/api/settings/npm')
  Object.assign(form, { url: '', email: '', password: '', system_id: null })
  await load()
}

const certTone = (d) => (d == null || d < 7 ? 'danger' : d < 20 ? 'warning' : 'ok')
const certText = (d) => (d == null ? 'unreadable' : d < 0 ? `expired ${Math.abs(Math.round(d))} d ago` : `${Math.round(d)} d`)
const sysName = (id) => systems.value.find((s) => s.id === Number(id))?.name || `#${id}`
onMounted(load)
useLive(['settings', 'findings'], load, 3000)
</script>

<template>
  <SettingsCard icon="link" title="Internet exposure" subtitle="Reads your proxy, router and tunnels to learn which containers the internet can reach" :status="status">
    <SettingsList label="Exposure sources">
      <SettingsEntry id="set-npm" icon="link" title="Nginx Proxy Manager"
                     :meta="npm?.config ? [`${npm.config.url} · user ${npm.config.email} · runs on ${npm.config.system_id ? sysName(npm.config.system_id) : 'no host chosen'}`,
                                           lastRead(npm.state, () => `${npm.state.hosts} proxy hosts, ${exposedCount} containers internet-exposed`)]
                       : 'Reads the proxy hosts and the expiry dates of their TLS certificates'">
        <template #badge><span :class="['badge', sourceState(npm?.config, npm?.state).tone]">{{ sourceState(npm?.config, npm?.state).text }}</span></template>
        <template v-if="npm?.config" #actions>
          <button type="button" class="btn-sm" :disabled="busy" @click="testNpm"><Icon name="refresh" :size="14" />Test</button>
          <button type="button" class="btn-sm btn-delete" :disabled="busy" @click="removeNpm"><Icon name="trash" :size="14" />Remove</button>
        </template>
        <template v-if="npm?.config">
          <p v-if="npm.state?.cert_note" class="message error">{{ npm.state.cert_note }}</p>
          <SettingsFold v-if="npm.state?.unmatched?.length" class="more" :title="`${npm.state.unmatched.length} proxy targets without a clear container – mark them on the host`">
            <div>
              <span v-for="u in npm.state.unmatched" :key="u.target + u.domains[0]" class="more-line"><span class="mono">{{ u.domains.join(', ') }} → {{ u.target }}</span> · {{ u.reason }}</span>
            </div>
          </SettingsFold>
          <p v-if="npm.state?.dns_failed?.length" class="message error" data-test="npm-dns-failed">
            Public DNS check failed for
            <span v-for="n in npm.state.dns_failed" :key="n"><span class="mono">{{ n }}</span>
              (<button type="button" class="link" :disabled="busy" @click="setMark([n], 'lan')">LAN only</button>) </span>
            – counted as internet-exposed.
          </p>
          <SettingsFold v-if="npm.state?.lan_only?.length" class="more" data-test="npm-lan-only" :title="`${npm.state.lan_only.length} proxy hosts only reachable in the LAN – not counted as internet-exposed`">
            <div>
              <span v-for="u in npm.state.lan_only" :key="u.target + u.domains[0]" class="more-line"><span class="mono">{{ u.domains.join(', ') }} → {{ u.target }}</span> · {{ u.reason }}
                · <button type="button" class="link" :disabled="busy" @click="setMark(u.domains, 'public')">Count as public</button></span>
            </div>
          </SettingsFold>
          <SettingsFold v-if="marked.length" class="more" data-test="npm-marked" :title="`${marked.length} names marked by hand`">
            <div>
              <span v-for="[n, m] in marked" :key="n" class="more-line"><span class="mono">{{ n }}</span> · {{ m === 'public' ? 'public' : 'LAN only' }}
                · <button type="button" class="link" :disabled="busy" @click="setMark([n], null)">Undo</button></span>
            </div>
          </SettingsFold>
        </template>
        <SettingsFold id="set-npm-form" :title="npm?.config ? 'Edit connection' : 'Connect Nginx Proxy Manager'">
          <form class="settings-form" @submit.prevent="saveNpm">
            <div class="grid">
              <label><span class="field-label">Admin URL (port 81)</span><input v-model="form.url" name="npm_url" placeholder="http://npm.lan:81" autocomplete="off" required /></label>
              <label><span class="field-label">User e-mail</span><input v-model="form.email" name="npm_email" placeholder="vulnwatch@example.org" autocomplete="off" required /></label>
              <SecretField v-model="form.password" name="npm_password" label="Password" :set="!!npm?.password?.set" :updated-at="npm?.password?.updated_at" />
              <label>
                <span class="field-label">Host running NPM</span>
                <select v-model="form.system_id" name="npm_host">
                  <option :value="null">Choose a host…</option>
                  <option v-for="s in systems" :key="s.id" :value="s.id">{{ s.name }}</option>
                </select>
              </label>
            </div>
            <p class="subtext">A dedicated NPM user with item visibility “All items” and view-only rights is enough. vulnwatch never reads private keys, access lists or DNS credentials.</p>
            <div class="actions">
              <button class="primary" :disabled="busy || !form.url || !form.email"><Icon name="check" :size="15" />{{ busy ? 'Saving & testing…' : 'Save and test' }}</button>
            </div>
          </form>
        </SettingsFold>
      </SettingsEntry>

      <SettingsEntry id="set-fritz" icon="link" title="FRITZ!Box port forwards"
                     :meta="fritz?.config ? [`${fritz.config.url} · user ${fritz.config.user}`, lastRead(fritz.state, () => fritzText(fritz.state))]
                       : 'Reads the IPv4 port forwards, including services that bypass NPM'">
        <template #badge><span :class="['badge', sourceState(fritz?.config, fritz?.state).tone]">{{ sourceState(fritz?.config, fritz?.state).text }}</span></template>
        <template v-if="fritz?.config" #actions>
          <button type="button" class="btn-sm" :disabled="busy" @click="testFritz"><Icon name="refresh" :size="14" />Test</button>
          <button type="button" class="btn-sm btn-delete" :disabled="busy" @click="removeFritz"><Icon name="trash" :size="14" />Remove</button>
        </template>
        <SettingsFold v-if="fritz?.state?.unmatched?.length" class="more" :title="`${fritz.state.unmatched.length} port forwards without a clear container – mark them on the host`">
          <div>
            <span v-for="u in fritz.state.unmatched" :key="u.forward" class="more-line"><span class="mono">{{ u.forward }}</span>{{ u.description ? ` (${u.description})` : '' }} · {{ u.reason }}</span>
          </div>
        </SettingsFold>
        <SettingsFold id="set-fritz-form" :title="fritz?.config ? 'Edit connection' : 'Connect a FRITZ!Box'">
          <form class="settings-form" @submit.prevent="saveFritz">
            <div class="grid">
              <label><span class="field-label">TR-064 address (port 49000)</span><input v-model="fform.url" name="fritz_url" placeholder="http://192.168.178.1:49000" autocomplete="off" required /></label>
              <label><span class="field-label">User</span><input v-model="fform.user" name="fritz_user" placeholder="vulnwatch" autocomplete="off" required /></label>
              <SecretField v-model="fform.password" name="fritz_password" label="Password" :set="!!fritz?.password?.set" :updated-at="fritz?.password?.updated_at" />
            </div>
            <p class="subtext">The user needs the right “FRITZ!Box settings”, and “Allow access for applications” must be on (Home network › Network › Network settings).
              vulnwatch only reads the forwards. IPv6 releases are not visible over TR-064; mark those by hand.</p>
            <div class="actions">
              <button class="primary" :disabled="busy || !fform.url || !fform.user"><Icon name="check" :size="15" />{{ busy ? 'Saving & testing…' : 'Save and test' }}</button>
            </div>
          </form>
        </SettingsFold>
      </SettingsEntry>

      <RouterForwardsSettings />

      <SettingsEntry id="set-cf" icon="link" title="Cloudflare Tunnel"
                     :meta="cf?.config ? [`Account ${cf.config.account_id}`, lastRead(cf.state, () => cfText(cf.state))]
                       : 'Reads the public hostnames of your tunnels with a read-only API token'">
        <template #badge><span :class="['badge', sourceState(cf?.config, cf?.state).tone]">{{ sourceState(cf?.config, cf?.state).text }}</span></template>
        <template v-if="cf?.config" #actions>
          <button type="button" class="btn-sm" :disabled="busy" @click="testCf"><Icon name="refresh" :size="14" />Test</button>
          <button type="button" class="btn-sm btn-delete" :disabled="busy" @click="removeCf"><Icon name="trash" :size="14" />Remove</button>
        </template>
        <SettingsFold v-if="cf?.state?.unmatched?.length" class="more" data-test="cf-unmatched" :title="`${cf.state.unmatched.length} tunnel routes without a clear container – mark them on the host`">
          <div>
            <span v-for="u in cf.state.unmatched" :key="u.what + (u.service || '')" class="more-line"><span class="mono">{{ u.what }}{{ u.service ? ` → ${u.service}` : '' }}</span> · {{ u.why }}</span>
          </div>
        </SettingsFold>
        <SettingsFold id="set-cf-form" :title="cf?.config ? 'Edit connection' : 'Connect Cloudflare'">
          <form class="settings-form" @submit.prevent="saveCf">
            <div class="grid">
              <label><span class="field-label">Account ID</span><input v-model="cform.account_id" name="cf_account" placeholder="32 hex characters" autocomplete="off" required /></label>
              <SecretField v-model="cform.token" name="cf_token" label="API token" :set="!!cf?.token?.set" :updated-at="cf?.token?.updated_at" />
            </div>
            <p class="subtext">Create a token with only “Account · Cloudflare Tunnel · Read”. Tunnels managed with a local config.yml can't be read; mark their services by hand.</p>
            <div class="actions">
              <button class="primary" :disabled="busy || !cform.account_id"><Icon name="check" :size="15" />{{ busy ? 'Saving & testing…' : 'Save and test' }}</button>
            </div>
          </form>
        </SettingsFold>
      </SettingsEntry>

      <SettingsEntry v-if="traefik?.configured" id="set-traefik" icon="link" title="Traefik (Docker labels)" data-test="traefik"
                     :meta="`Read from the labels the agents report: ${traefik.routers} routers, ${Object.values(traefik.exposed || {}).flat().length} containers internet-exposed`">
        <template #badge><span class="badge neutral">Automatic</span></template>
        <span class="subtext">Only the Docker provider on the same host is visible, not routes from Traefik's file provider.</span>
        <p v-if="traefik.dns_failed?.length" class="message error">Public DNS check failed for {{ traefik.dns_failed.join(', ') }} – counted as internet-exposed.</p>
        <SettingsFold v-if="traefik.lan_only?.length" class="more" :title="`${traefik.lan_only.length} routers only reachable in the LAN – not counted as internet-exposed`">
          <div>
            <span v-for="u in traefik.lan_only" :key="u.what + u.router" class="more-line"><span class="mono">{{ u.domains.join(', ') }}</span> → {{ u.what }} · {{ u.reason }}
              · <button type="button" class="link" :disabled="busy" @click="setMark(u.domains, 'public')">Count as public</button></span>
          </div>
        </SettingsFold>
        <SettingsFold v-if="traefik.unmatched?.length" class="more" data-test="traefik-unmatched" :title="`${traefik.unmatched.length} routers that cannot be checked – mark them on the host`">
          <div>
            <span v-for="u in traefik.unmatched" :key="u.what + (u.router || '')" class="more-line"><span class="mono">{{ u.what }}{{ u.router ? ` (router ${u.router})` : '' }}</span> · {{ u.why }}</span>
          </div>
        </SettingsFold>
        <SettingsFold v-if="traefik.entrypoints?.length" id="set-traefik-entrypoints" title="Entrypoints"
                      hint="decide per entrypoint whether its routers count as public">
          <div class="entrypoints" data-test="traefik-entrypoints">
            <label v-for="e in traefik.entrypoints" :key="e"><span class="field-label mono">{{ e }}</span>
              <select :name="`ep_${e}`" :value="npm?.overrides?.entrypoints?.[e] || ''" :disabled="busy" @change="setEntrypoint(e, $event.target.value)">
                <option value="">decide by public DNS</option><option value="public">always public</option><option value="lan">LAN only</option>
              </select>
            </label>
          </div>
        </SettingsFold>
      </SettingsEntry>
    </SettingsList>

    <SettingsFold v-if="certs.length" id="set-certs" title="TLS certificates in use"
                  :hint="`${certs.length} from NPM · next expires in ${certText(nextExpiry)}`">
      <span class="subtext">NPM renews 30 days ahead. Under 20 days left counts as medium, under 7 days or expired as high.</span>
      <SettingsList>
        <SettingsEntry v-for="c in certs" :key="c.name" dense mono :title="c.domains.join(', ') || c.name">
          <template #actions><span :class="['days', certTone(c.days_left)]" :title="c.expires_on ? `expires ${fmtStamp(c.expires_on)}` : ''">{{ certText(c.days_left) }}</span></template>
        </SettingsEntry>
      </SettingsList>
    </SettingsFold>

    <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
  </SettingsCard>
</template>

<style scoped>
.more-line { display: block; font-size: 0.75rem; color: var(--muted); padding: 0.125rem 0; overflow-wrap: anywhere; }
.more-line .mono { color: var(--text-2); }
/* Restlaufzeit: Zahl in der Ampelfarbe statt einer Pille je Zeile */
.days { font: 0.75rem var(--mono); font-variant-numeric: tabular-nums; white-space: nowrap; }
.days.ok { color: var(--ok); }
.days.warning { color: var(--med); }
.days.danger { color: var(--crit); font-weight: 600; }
.entrypoints { display: flex; flex-wrap: wrap; gap: 0.75rem; }
</style>
