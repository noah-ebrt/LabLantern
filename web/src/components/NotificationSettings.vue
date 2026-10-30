<script setup>
import { onMounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import Icon from './Icon.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import SettingsSection from './SettingsSection.vue'

const channels = ref([])
const showAddForm = ref(false)
const channelType = ref('mail') // 'mail' | 'apprise'

const form = reactive({ name: '', url: '' })
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
  channels.value = (await api.get('/api/integrations/notifications')).channels
}

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

const addMail = () => run(async () => {
  await api.post('/api/integrations/notifications/smtp', { ...mail, port: Number(mail.port) })
  mail.password = ''
  showAddForm.value = false
  await load()
}, 'Mail channel saved. Verify delivery using “Send test notification”.')

const test = () => run(() => api.post('/api/integrations/notifications/test'), 'Test notification sent to all channels.')

onMounted(() => run(load))
</script>

<template>
  <SettingsCard icon="bell" title="Notification Channels" subtitle="Receive immediate vulnerability warnings and daily scan reports">
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
          Send test notification
        </button>
    </template>

    <SettingsSection title="Channels" :count="channels.length" hint="URLs and passwords stored encrypted, never shown again">
      <SettingsList :empty="!channels.length" empty-text="No channel yet: alerts and scan reports currently go nowhere.">
        <SettingsEntry v-for="ch in channels" :key="ch.index" :icon="ch.scheme === 'mailtos' || ch.scheme === 'mailto' ? 'mail' : 'bell'"
                       :title="ch.name">
          <template #badge><span class="badge neutral mono">{{ ch.scheme }}</span></template>
          <template #actions>
            <button type="button" class="btn-sm btn-delete" data-test="remove-channel" :disabled="busy" @click="remove(ch)">
              <Icon name="trash" :size="14" />Remove
            </button>
          </template>
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
          <h3>Add Notification Channel</h3>
          <p class="subtitle">Choose channel type and enter credentials</p>
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
          :aria-selected="channelType === 'apprise'"
          :class="['seg-btn', { active: channelType === 'apprise' }]"
          data-test="tab-apprise"
          @click="channelType = 'apprise'"
        >
          <Icon name="bell" :size="16" />
          Push & Webhooks (Apprise)
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

      <!-- Push / Apprise URL Form -->
      <form v-else class="channel-form" @submit.prevent="add">
        <p class="hint">
          Connect mobile push or team chats via Apprise URLs, e.g. <code>ntfy://topic</code>,
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
/* Add Channel Form Panel */
.add-channel-panel {
  padding: 1.1rem 1.15rem;
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
  margin-bottom: 1.1rem;
}

.panel-heading h3 {
  margin: 0;
  font-size: 1rem;
}

.panel-heading .subtitle {
  margin: 0.2rem 0 0;
  font-size: 0.84rem;
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

.channel-type { margin-bottom: 1.1rem; }

.channel-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
</style>
