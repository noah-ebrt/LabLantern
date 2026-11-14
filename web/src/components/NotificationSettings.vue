<script setup>
import { onMounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import Icon from './Icon.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import SettingsSection from './SettingsSection.vue'
import ToggleSwitch from './ToggleSwitch.vue'

const channels = ref([])
const events = ref([])
const defaults = ref({})
const open = ref({})  // Kanal-Index → Arten aufgeklappt
const showAddForm = ref(false)
const channelType = ref('mail') // 'mail' | 'ntfy' | 'apprise'

const form = reactive({ name: '', url: '' })
const ntfy = reactive({ name: 'Push (ntfy)', server: 'ntfy.sh', topic: '', token: '', username: '', password: '' })
const mail = reactive({
  name: 'Mail',
  host: '',
  port: 587,
  security: 'starttls',
  username: '',
  password: '',
  from_addr: '',
  to_addr: '',
})

// Vorbelegte Provider: nur Adresse, App-Passwort und Empfänger sind noch nötig.
const providers = {
  gmail: { label: 'Gmail', host: 'smtp.gmail.com', port: 587, security: 'starttls', hint: 'Google account → Security → App passwords (2-step verification required).' },
  icloud: { label: 'iCloud', host: 'smtp.mail.me.com', port: 587, security: 'starttls', hint: 'appleid.apple.com → App-specific passwords. The sender must be your iCloud address.' },
  outlook: { label: 'Outlook / Hotmail', host: 'smtp-mail.outlook.com', port: 587, security: 'starttls', hint: 'With two-step verification enabled, use an app password.' },
  gmx: { label: 'GMX', host: 'mail.gmx.net', port: 587, security: 'starttls', hint: 'Allow POP3/IMAP/SMTP access in the GMX settings.' },
  webde: { label: 'WEB.DE', host: 'smtp.web.de', port: 587, security: 'starttls', hint: 'Allow POP3/IMAP/SMTP access in the WEB.DE settings.' },
  posteo: { label: 'Posteo', host: 'posteo.de', port: 587, security: 'starttls', hint: '' },
  custom: { label: 'Custom server', host: '', port: 587, security: 'starttls', hint: '' },
}

const provider = ref('gmail')

function applyProvider() {
  const p = providers[provider.value]
  Object.assign(mail, {
    host: p.host,
    port: p.port,
    security: p.security,
    name: p.label === 'Custom server' ? 'Mail' : `Mail (${p.label})`,
  })
}
applyProvider()

function syncUser() {
  if (provider.value !== 'custom') mail.username = mail.from_addr
}

const message = ref(null)
const busy = ref(false)

async function run(fn, okText) {
  busy.value = true
  message.value = null
  try {
    const r = await fn()
    message.value = r && r.ok === false ? { kind: 'error', text: r.error } : okText ? { kind: 'ok', text: okText } : null
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}

async function load() {
  const r = await api.get('/api/integrations/notifications')
  channels.value = r.channels.map((c) => ({ enabled: true, events: {}, ...c }))
  events.value = r.events || []
  defaults.value = r.defaults || {}
}

// Was ein Kanal tatsächlich bekommt: eigene Einstellung vor der Vorgabe
const gets = (ch, id) => ch.enabled && (ch.events[id] ?? defaults.value[id] ?? true)
function summary(ch) {
  if (!ch.enabled) return 'Switched off: gets nothing'
  const on = events.value.filter((e) => gets(ch, e.id))
  const own = Object.keys(ch.events).length ? '' : ' (defaults)'
  if (!on.length) return 'Gets nothing'
  return on.length === events.value.length ? `Gets everything${own}` : `Gets ${on.map((e) => e.label.toLowerCase()).join(', ')}${own}`
}
const choice = (ch, id) => (id in ch.events ? (ch.events[id] ? 'on' : 'off') : 'default')

const setDefault = (id, value) => run(async () => {
  const r = await api.put('/api/integrations/notifications/defaults', { defaults: { [id]: value } })
  defaults.value = r.defaults || { ...defaults.value, [id]: value }
}, 'Default saved.')

const setEnabled = (ch, value) => run(async () => {
  await api.put(`/api/integrations/notifications/${ch.index}`, { enabled: value })
  await load()
}, value ? `${ch.name} is on.` : `${ch.name} is off.`)

const setEvent = (ch, id, value) => run(async () => {
  const v = value === 'default' ? null : value === 'on'
  await api.put(`/api/integrations/notifications/${ch.index}`, { events: { [id]: v } })
  await load()
}, 'Channel updated.')

const testOne = (ch) => run(() => api.post(`/api/integrations/notifications/${ch.index}/test`), `Test sent to ${ch.name}.`)

function openAdd(type = 'mail') {
  channelType.value = type
  showAddForm.value = true
  message.value = null
}

function closeAdd() {
  showAddForm.value = false
}

const add = () => run(async () => {
  await api.post('/api/integrations/notifications', { name: form.name.trim(), url: form.url.trim() })
  form.name = ''
  form.url = ''
  showAddForm.value = false
  await load()
}, 'Push channel saved.')

const remove = (ch) => {
  if (!confirm(`Remove the channel “${ch.name}”? Alerts no longer reach it.`)) return
  run(async () => {
    await api.del(`/api/integrations/notifications/${ch.index}`)
    await load()
  }, 'Channel removed.')
}

const addNtfy = () => run(async () => {
  await api.post('/api/integrations/notifications/ntfy', { ...ntfy, name: ntfy.name.trim(), topic: ntfy.topic.trim() })
  Object.assign(ntfy, { topic: '', token: '', username: '', password: '' })
  showAddForm.value = false
  await load()
}, 'Push channel saved. Subscribe to the topic in the ntfy app, then send a test.')

const addMail = () => run(async () => {
  await api.post('/api/integrations/notifications/smtp', { ...mail, port: Number(mail.port) })
  mail.password = ''
  showAddForm.value = false
  await load()
}, 'Mail channel saved. Verify delivery using “Send test notification”.')

// Thema, das niemand errät: 16 Zeichen aus a–z und 0–9 (≈ 82 Bit)
function randomTopic() {
  const abc = 'abcdefghijklmnopqrstuvwxyz0123456789'
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  ntfy.topic = 'lablantern-' + Array.from(bytes, (b) => abc[b % abc.length]).join('')
}

const test = () => run(() => api.post('/api/integrations/notifications/test'), 'Test notification sent to all channels.')

onMounted(() => run(load))

// Apprise-Schema als Name, den man kennt; unbekannte Schemata bleiben, wie sie sind
const SCHEMES = { mailto: 'Mail', mailtos: 'Mail', ntfy: 'ntfy', ntfys: 'ntfy', tgram: 'Telegram', discord: 'Discord', slack: 'Slack',
  msteams: 'Teams', json: 'Webhook', jsons: 'Webhook', gotify: 'Gotify', gotifys: 'Gotify', pover: 'Pushover', signal: 'Signal', signals: 'Signal' }
const schemeLabel = (s) => SCHEMES[s] || s
</script>

<template>
  <SettingsCard icon="bell" title="Channels" subtitle="Where alerts and scan reports go: mail, push or chat">
    <template #actions>
        <button
          v-if="!showAddForm"
          type="button"
          class="primary"
          data-test="add-channel"
          @click="openAdd('mail')"
        >
          <Icon name="plus" :size="15" />
          Add channel
        </button>
        <button
          type="button"
          data-test="test-notify"
          :disabled="busy || !channels.length"
          @click="test"
        >
          <Icon name="refresh" :size="15" />
          Test all channels
        </button>
    </template>

    <SettingsSection title="What gets sent" hint="The default for every channel. Each channel can switch single notifications on or off under “Choose”.">
      <div class="defaults" data-test="defaults">
        <ul class="defaults-list" aria-label="Default notifications">
          <li v-for="ev in events" :key="ev.id" class="default-row">
            <label class="default-text" :for="`notify-default-${ev.id}`">
              <span class="default-name">{{ ev.label }}</span>
              <span :id="`notify-default-hint-${ev.id}`" class="default-hint">{{ ev.hint }}</span>
            </label>
            <ToggleSwitch :id="`notify-default-${ev.id}`" :model-value="defaults[ev.id] !== false" :name="`default_${ev.id}`"
                          :label="ev.label" :describedby="`notify-default-hint-${ev.id}`" :disabled="busy"
                          :data-test="`default-${ev.id}`" @update:model-value="(v) => setDefault(ev.id, v)" />
          </li>
        </ul>
      </div>
    </SettingsSection>

    <SettingsSection title="Configured" :count="channels.length" hint="URLs and passwords are stored encrypted and never shown again">
      <SettingsList :empty="!channels.length" empty-text="No channel yet: alerts and scan reports currently go nowhere.">
        <SettingsEntry v-for="ch in channels" :key="ch.index" :icon="ch.scheme === 'mailtos' || ch.scheme === 'mailto' ? 'mail' : 'bell'"
                       :title="ch.name" :meta="summary(ch)">
          <template #badge><span class="badge neutral">{{ schemeLabel(ch.scheme) }}</span></template>
          <template #actions>
            <ToggleSwitch :model-value="ch.enabled" :name="`channel_on_${ch.index}`" :label="ch.enabled ? 'On' : 'Off'"
                          :disabled="busy" data-test="channel-enabled" @update:model-value="(v) => setEnabled(ch, v)" />
            <button type="button" class="btn-sm" data-test="channel-customize" :aria-expanded="!!open[ch.index]"
                    @click="open[ch.index] = !open[ch.index]">
              <Icon name="settings" :size="14" />{{ open[ch.index] ? 'Done' : 'Choose' }}
            </button>
            <button type="button" class="btn-sm" data-test="test-channel" :disabled="busy" @click="testOne(ch)">
              <Icon name="refresh" :size="14" />Test
            </button>
            <button type="button" class="btn-sm btn-delete" data-test="remove-channel" :disabled="busy" @click="remove(ch)">
              <Icon name="trash" :size="14" />Remove
            </button>
          </template>
          <div v-if="open[ch.index]" class="event-grid" data-test="channel-events">
            <label v-for="ev in events" :key="ev.id" class="event-row">
              <span class="event-label">{{ ev.label }}</span>
              <select :value="choice(ch, ev.id)" :name="`ev_${ch.index}_${ev.id}`" :disabled="busy || !ch.enabled"
                      @change="setEvent(ch, ev.id, $event.target.value)">
                <option value="default">Default ({{ defaults[ev.id] === false ? 'off' : 'on' }})</option>
                <option value="on">On</option>
                <option value="off">Off</option>
              </select>
            </label>
          </div>
        </SettingsEntry>
        <template #empty>
          <button v-if="!showAddForm" type="button" class="primary" @click="openAdd('mail')"><Icon name="plus" :size="15" />Add your first channel</button>
        </template>
      </SettingsList>
    </SettingsSection>

    <!-- Hidden Form by Default: Opens on Add Channel -->
    <div v-if="showAddForm" class="add-channel-panel">
      <div class="panel-header">
        <div class="panel-heading">
          <h3>Add a channel</h3>
          <p class="subtitle">Mail over SMTP, or push and chat through Apprise</p>
        </div>
        <button
          type="button"
          class="close-btn"
          aria-label="Close add channel form"
          @click="closeAdd"
        >
          <Icon name="x" :size="16" />
        </button>
      </div>

      <!-- Channel Type Tabs -->
      <div class="seg channel-type" role="tablist" aria-label="Channel type">
        <button
          type="button"
          role="tab"
          :aria-selected="channelType === 'mail'"
          :class="['seg-btn', { active: channelType === 'mail' }]"
          data-test="tab-mail"
          @click="channelType = 'mail'"
        >
          <Icon name="mail" :size="16" />
          Email (SMTP)
        </button>
        <button
          type="button"
          role="tab"
          :aria-selected="channelType === 'ntfy'"
          :class="['seg-btn', { active: channelType === 'ntfy' }]"
          data-test="tab-ntfy"
          @click="channelType = 'ntfy'"
        >
          <Icon name="bell" :size="16" />
          Push (ntfy)
        </button>
        <button
          type="button"
          role="tab"
          :aria-selected="channelType === 'apprise'"
          :class="['seg-btn', { active: channelType === 'apprise' }]"
          data-test="tab-apprise"
          @click="channelType = 'apprise'"
        >
          <Icon name="link" :size="16" />
          Other (Apprise)
        </button>
      </div>

      <!-- Email (SMTP) Form -->
      <form v-if="channelType === 'mail'" class="channel-form" @submit.prevent="addMail">
        <div class="grid">
          <label>
            Provider
            <select v-model="provider" name="provider" @change="applyProvider">
              <option v-for="(p, key) in providers" :key="key" :value="key">{{ p.label }}</option>
            </select>
          </label>
          <label>
            Sender address
            <input
              v-model="mail.from_addr"
              name="from_addr"
              type="email"
              required
              placeholder="alerts@example.org"
              @input="syncUser"
            />
          </label>
          <label>
            {{ provider === 'custom' ? 'Password' : 'App password' }}
            <input
              v-model="mail.password"
              name="password"
              type="password"
              autocomplete="new-password"
              required
              placeholder="••••••••••••"
            />
          </label>
          <label>
            Alert recipient
            <input
              v-model="mail.to_addr"
              name="to_addr"
              type="email"
              required
              placeholder="admin@example.org"
            />
          </label>
          <template v-if="provider === 'custom'">
            <label>
              SMTP Server
              <input v-model="mail.host" name="host" required placeholder="smtp.example.org" />
            </label>
            <label>
              Port
              <input v-model="mail.port" name="port" type="number" min="1" max="65535" required />
            </label>
            <label>
              Encryption
              <select v-model="mail.security" name="security">
                <option value="starttls">STARTTLS (usually port 587)</option>
                <option value="ssl">SSL/TLS (usually port 465)</option>
                <option value="none">none</option>
              </select>
            </label>
            <label>
              Username
              <input v-model="mail.username" name="username" autocomplete="off" />
            </label>
          </template>
        </div>

        <p v-if="providers[provider].hint" class="hint">{{ providers[provider].hint }}</p>
        <p v-else-if="provider !== 'custom'" class="hint">Server {{ mail.host }}:{{ mail.port }} ({{ mail.security }}) is preset.</p>

        <div class="actions">
          <button type="submit" class="primary" :disabled="busy">
            <Icon name="check" :size="15" />
            Save email channel
          </button>
          <button type="button" class="secondary" @click="closeAdd">
            Cancel
          </button>
        </div>
      </form>

      <!-- ntfy push -->
      <form v-else-if="channelType === 'ntfy'" class="channel-form" @submit.prevent="addNtfy">
        <p class="hint">
          Push to your phone with the ntfy app. Pick a topic name nobody can guess (on ntfy.sh anyone who knows it can read
          along), subscribe to it in the app, then save.
        </p>
        <div class="grid">
          <label>
            Channel name
            <input v-model="ntfy.name" name="ntfy_name" maxlength="60" required />
          </label>
          <label>
            Server
            <input v-model="ntfy.server" name="ntfy_server" class="mono" required placeholder="ntfy.sh or https://ntfy.example.org" />
          </label>
          <div class="field">
            <label for="ntfy-topic">Topic</label>
            <div class="input-row">
              <input id="ntfy-topic" v-model="ntfy.topic" name="ntfy_topic" class="mono" required pattern="[A-Za-z0-9_\-]+"
                     maxlength="64" autocomplete="off" spellcheck="false" placeholder="lab-alerts-7f3k" />
              <button type="button" data-test="ntfy-random-topic" title="Fill in a random topic nobody can guess" @click="randomTopic">
                <Icon name="refresh" :size="14" />Random
              </button>
            </div>
          </div>
          <label>
            <span class="field-head">Access token <span class="optional">optional</span></span>
            <input v-model="ntfy.token" name="ntfy_token" type="password" autocomplete="off" placeholder="tk_…" />
          </label>
        </div>
        <details class="fold">
          <summary><Icon name="chevron" :size="14" class="chev" />Username and password instead of a token</summary>
          <div class="grid">
            <label>
              Username
              <input v-model="ntfy.username" name="ntfy_username" autocomplete="off" />
            </label>
            <label>
              Password
              <input v-model="ntfy.password" name="ntfy_password" type="password" autocomplete="new-password" />
            </label>
          </div>
        </details>
        <p class="subtext priorities">Outages arrive as urgent, alerts and early warnings as high, reports quietly.</p>
        <div class="actions">
          <button type="submit" class="primary" :disabled="busy">
            <Icon name="check" :size="15" />
            Save push channel
          </button>
          <button type="button" class="secondary" @click="closeAdd">
            Cancel
          </button>
        </div>
      </form>

      <!-- Push / Apprise URL Form -->
      <form v-else class="channel-form" @submit.prevent="add">
        <p class="hint">
          Connect other push services or team chats via Apprise URLs, e.g. <code>gotify://host/token</code>,
          <code>tgram://bottoken/chat_id</code>, or <code>discord://webhook_id/token</code>.
          The URL is encrypted at rest and never displayed.
        </p>
        <div class="grid">
          <label>
            Channel name
            <input
              v-model="form.name"
              name="name"
              maxlength="60"
              required
              placeholder="Phone (ntfy) or Slack #security"
            />
          </label>
          <label>
            Apprise URL
            <input
              v-model="form.url"
              name="url"
              type="password"
              autocomplete="off"
              required
              placeholder="ntfy://alerts or tgram://..."
            />
          </label>
        </div>
        <div class="actions">
          <button type="submit" class="primary" :disabled="busy">
            <Icon name="check" :size="15" />
            Add push channel
          </button>
          <button type="button" class="secondary" @click="closeAdd">
            Cancel
          </button>
        </div>
      </form>
    </div>

    <p v-if="message" class="message" :class="message.kind" role="status">
      {{ message.text }}
    </p>
  </SettingsCard>
</template>

<style scoped>
/* Vorgaben: eingelassene Liste wie „Configured“, Name und Erklärung links, Schalter rechts.
   Spalten nach der Breite der Karte; Trennlinien per Rahmen, damit auch eine ungerade Anzahl sauber bleibt. */
.defaults { container-type: inline-size; }
.defaults-list {
  list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: minmax(0, 1fr); overflow: hidden;
  border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--ground);
}
.default-row {
  display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 0.75rem 1rem;
  margin: -1px 0 0 -1px; border-top: 1px solid var(--line); border-left: 1px solid var(--line);
}
.default-row > .toggle-wrapper { flex: none; }
.default-text { flex: 1; min-width: 0; gap: 0.125rem; cursor: pointer; }
.default-name { font-size: 0.875rem; font-weight: 500; color: var(--text); }
.default-hint { font-size: 0.8125rem; color: var(--muted); text-wrap: pretty; }
@container (min-width: 44rem) { .defaults-list { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@container (min-width: 72rem) { .defaults-list { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
.event-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(15rem, 1fr)); gap: 0.5rem 1rem; padding-top: 0.5rem; }
.event-row { flex-direction: row; align-items: center; justify-content: space-between; gap: 0.75rem; font-size: 0.8125rem; }
.event-label { color: var(--text-2); }
.event-row select { width: auto; min-height: 30px; padding-top: 0.25rem; padding-bottom: 0.25rem; font-size: 0.8125rem; }
.optional { color: var(--muted); font-size: 0.75rem; font-weight: 400; }
/* Formulare im Panel: höchstens zwei Spalten in Lesebreite statt vier überbreiter Felder */
.channel-form .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem 1.25rem; max-width: 48rem; }
.channel-form .hint { margin: 0; max-width: 68ch; font-size: 0.8125rem; line-height: 1.55; text-wrap: pretty; }
.field { display: flex; flex-direction: column; gap: 0.25rem; min-width: 0; }
.field-head { display: flex; align-items: baseline; gap: 0.5rem; }
.input-row { display: flex; gap: 0.5rem; }
.input-row input { flex: 1; min-width: 0; }
.input-row button { flex: none; }
.priorities { margin: 0; }
.fold { max-width: 48rem; }
.fold summary {
  display: inline-flex; align-items: flex-start; gap: 0.5rem; list-style: none; cursor: pointer;
  font-size: 0.8125rem; color: var(--text-2); border-radius: 4px;
}
.fold summary::-webkit-details-marker { display: none; }
.fold summary:hover { color: var(--text); }
.fold summary:focus-visible { outline: 2px solid var(--text-2); outline-offset: 3px; }
.fold .chev { flex: none; margin-top: 0.1875rem; color: var(--muted); transition: transform 0.2s var(--ease); }
.fold[open] .chev { transform: rotate(90deg); }
.fold[open] summary { margin-bottom: 0.75rem; }
@media (max-width: 560px) { .channel-form .grid { grid-template-columns: minmax(0, 1fr); } }
/* Add Channel Form Panel */
.add-channel-panel {
  padding: 1.25rem;
  background: var(--ground);
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  animation: slideDown 0.2s var(--ease);
}

@keyframes slideDown {
  from {
    opacity: 0;
    transform: translateY(-6px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.panel-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
}

.panel-heading h3 {
  margin: 0;
  font-size: 1rem;
}

.panel-heading .subtitle {
  margin: 0.25rem 0 0;
  font-size: 0.8125rem;
}

.close-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 30px;
  height: 30px;
  padding: 0;
  border-radius: var(--radius-sm);
  background: transparent;
  border: 1px solid transparent;
  color: var(--muted);
}

.close-btn:hover {
  color: var(--text);
  background: var(--surface-3);
  border-color: var(--line-strong);
}

.channel-type { margin-bottom: 1rem; }

.channel-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
</style>
