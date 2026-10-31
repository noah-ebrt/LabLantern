<script setup>
import { reactive, ref } from 'vue'
import { api } from '../api.js'
import Icon from './Icon.vue'
import SecretField from './SecretField.vue'

// Anleitung und Formular für ein Gerät ohne Agent (TrueNAS, Home Assistant): was gelesen wird, was vorher auf dem
// Gerät einzurichten ist, welche API-Aufrufe vulnwatch macht. Mit `entry` wird eine bestehende Verbindung bearbeitet.
const props = defineProps({
  kind: { type: String, required: true },     // truenas | homeassistant | proxmox | synology | opnsense
  entry: { type: Object, default: null },     // aus /api/settings/appliances
})
const emit = defineEmits(['saved'])

const GUIDES = {
  synology: {
    title: 'Synology DSM',
    reads: ['DSM version and model (any account)',
      'A newer DSM from DSM’s own update check: same line → high, new line → medium',
      'Storage pools, volumes and drives: degraded or crashed → high, a failing drive (status or S.M.A.R.T.) → high, a volume 90 % full → medium, 95 % → high',
      'Installed packages (Container Manager, Synology Photos, …) with versions, for the early warning'],
    steps: [
      'Control Panel → User &amp; Group → Create: a user <code>vulnwatch</code> with a long random password.',
      'Put it in the <strong>administrators</strong> group: DSM has no read-only role, and only administrators may read the update check, packages and storage. Without it vulnwatch reads only the version and shows the rest as n/a.',
      'Deny it everything it does not need: under <strong>Applications</strong> deny all (File Station, SMB, AFP, FTP …), under <strong>Permissions</strong> no access to shared folders. vulnwatch only uses the DSM Web API.',
      'No 2-factor authentication for this user (exempt it if 2FA is enforced) and make sure Auto Block does not list vulnwatch’s IP.',
      'Enter <code>https://&lt;nas&gt;:5001</code>, the account and its password.',
    ],
    url: 'https://nas.lan:5001', secret: 'Password', account: 'Account',
    api: [
      ['Connection', 'HTTPS to &lt;nas&gt;:5001, certificate pinned when saved; one session per read, logged out afterwards'],
      ['Requests', 'POST /webapi/entry.cgi: SYNO.API.Auth login/logout, SYNO.DSM.Info getinfo, SYNO.Core.Upgrade.Server check, SYNO.Core.Package list, SYNO.Storage.CGI.Storage load_info'],
      ['Writes', 'none'],
    ],
  },
  opnsense: {
    title: 'OPNsense',
    reads: ['Installed version and the result of the firewall’s last update check: a newer OPNsense (same line → high, new line → medium), other pending package updates (medium), a major upgrade (medium)',
      'End of life of the release line from endoflife.date',
      'Installed plugins (os-wireguard, os-haproxy, …) with versions, for the early warning'],
    steps: [
      'System → Access → Users → Add: a user <code>vulnwatch</code> without login shell, password scrambled.',
      'Give it the privilege <strong>System: Firmware</strong> (Effective Privileges). For the port forwards under Settings → Exposure it also needs <strong>Firewall: NAT: Destination NAT</strong>; the same key works for both.',
      'In the user, under API keys, click <strong>+</strong>: OPNsense downloads a file with <code>key=</code> and <code>secret=</code>.',
      'Enter <code>https://&lt;firewall&gt;</code>, the key and the secret. vulnwatch does not start an update check itself: it reads the result of the last check on the firewall (System → Firmware → Status → Check for updates). A regular check can be scheduled under System → Settings → Cron.',
    ],
    url: 'https://opnsense.lan', secret: 'API secret', account: 'API key',
    api: [
      ['Connection', 'HTTPS to &lt;firewall&gt;:443, certificate pinned when saved'],
      ['Requests', 'GET /api/core/firmware/status, /api/core/firmware/info'],
      ['Header', 'Authorization: Basic &lt;key:secret&gt;'],
      ['Writes', 'none'],
    ],
  },
  truenas: {
    title: 'TrueNAS',
    reads: ['Installed version and the system update check (patch → high, new release line → medium)',
      'Apps with a newer version or image', 'Open alerts (CRITICAL → high, ERROR and WARNING → medium)', 'Pending reboot after an update',
      'Pools with layout and fill level, every drive with model, size and temperature: a faulted drive → high, read/write/checksum errors → medium'],
    steps: [
      'Credentials → Users → Add: a user named <code>vulnwatch</code> with the role <strong>Read-only Administrator</strong>.',
      'Create an API key for that user (TrueNAS 24.10 and newer: Credentials → Users → the user → API keys). Older versions issue keys with full admin rights; update first if you can.',
      'Enter the address with <code>https://</code>. TrueNAS revokes a key that was ever sent over plain HTTP.',
    ],
    url: 'https://truenas.lan', secret: 'API key',
    api: [
      ['Connection', 'WebSocket wss://&lt;host&gt;/api/current, JSON-RPC 2.0 (before 24.10: /websocket)'],
      ['Login', 'auth.login_with_api_key'],
      ['Read calls', 'system.info · update.status (before 25.10: update.check_available) · alert.list · app.query (before 24.10: chart.release.query)'],
      ['Writes', 'none'],
    ],
  },
  proxmox: {
    title: 'Proxmox VE',
    reads: ['Proxmox VE version per node and a newer pve-manager (same line → high, new line → medium); end of life from endoflife.date',
      'Pending package updates per node (the agent on the node rates them; install it for package CVEs)',
      'Drives per node with S.M.A.R.T. health and ZFS pools with their drives: a failed drive or degraded pool → high, a pool 90 % full → medium',
      'Every VM and LXC with name, state and tags: each one is matched to an agent host by name, else by IP. Guests without an agent are gaps in the coverage; stopped ones can be excluded with a reason. Templates do not count.'],
    steps: [
      'Datacenter → Permissions → Users → Add: <code>vulnwatch@pve</code> (realm Proxmox VE authentication server), no password needed.',
      'Datacenter → Permissions → API Tokens → Add: user <code>vulnwatch@pve</code>, token ID <code>vulnwatch</code>, <strong>Privilege Separation off</strong>. Copy the secret.',
      'Datacenter → Permissions → Add → User Permission: path <code>/</code>, user <code>vulnwatch@pve</code>, role <strong>PVEAuditor</strong> (read-only).',
      'Enter <code>https://&lt;host&gt;:8006</code> and as token <code>vulnwatch@pve!vulnwatch=&lt;secret&gt;</code>. Older PVE releases only list pending updates with Sys.Modify; vulnwatch does not ask for it and shows that check as n/a.',
    ],
    url: 'https://pve.lan:8006', secret: 'API token (user@realm!id=secret)',
    api: [
      ['Connection', 'HTTPS to &lt;host&gt;:8006, certificate pinned when saved'],
      ['Requests', 'GET /api2/json/version, /nodes, /nodes/{node}/version, /nodes/{node}/apt/update, /cluster/resources?type=vm; for matching by IP /nodes/{node}/lxc/{id}/config and /nodes/{node}/qemu/{id}/agent/network-get-interfaces'],
      ['Header', 'Authorization: PVEAPIToken=&lt;user&gt;@&lt;realm&gt;!&lt;id&gt;=&lt;secret&gt;'],
      ['Writes', 'none'],
    ],
  },
  homeassistant: {
    title: 'Home Assistant',
    reads: ['Every update entity: Core, Operating System, Supervisor, add-ons, ESPHome and device firmware (same line → high, new line → medium; skipped versions are not reported)',
      'Age of the last successful automatic backup (over 3 days medium, over 7 days or never high) and failed backups',
      'Recovery or safe mode (high: integrations and automations are not loaded)',
      'Disk usage from System Monitor and the Supervisor (from 90 % medium, from 95 % high)',
      'Low batteries below 15 % (info), and the loaded integrations for the AI early warning'],
    steps: [
      'Settings → People → Users → Add user: <code>vulnwatch</code>, administrator off.',
      'Log in as that user, then Profile → Security → Long-lived access tokens → Create token.',
      'Enter the address with port, e.g. <code>http://homeassistant.lan:8123</code>. If the test says the token was rejected for a non-admin user, use an admin user instead.',
    ],
    url: 'http://homeassistant.lan:8123', secret: 'Access token',
    api: [
      ['Connection', 'HTTP(S) to &lt;host&gt;:8123'],
      ['Requests', 'GET /api/states and GET /api/config, with Authorization: Bearer &lt;token&gt;'],
      ['Used from states', 'update.*; sensor.backup_* timestamps; device_class battery; disk sensors (detected by device class and unit, so any language works)'],
      ['Used from config', 'state, safe_mode, recovery_mode, components. Never location or URLs'],
      ['Writes', 'none'],
    ],
  },
}
const g = GUIDES[props.kind]
const form = reactive({ name: props.entry?.name || props.kind,
  url: props.entry?.url || '', account: props.entry?.account || '', token: '' })
const message = ref(null)
const busy = ref(false)

async function save() {
  busy.value = true
  message.value = null
  try {
    const body = { kind: props.kind, name: form.name, url: form.url, token: form.token || null, ...(g.account ? { account: form.account } : {}) }
    const r = props.entry ? await api.put(`/api/settings/appliances/${props.entry.system_id}`, body)
      : await api.post('/api/settings/appliances', body)
    form.token = ''
    if (r.ok) emit('saved', `${form.name} connected: ${r.version || 'version unknown'}, ${r.findings} open update(s) or alert(s).`)
    else message.value = { kind: 'error', text: `Saved, but the device could not be read: ${r.error}. Fix it here and save again, or remove the host.` }
  } catch (e) {
    message.value = { kind: 'error', text: e.message }
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="guide">
    <section>
      <h3>What vulnwatch reads</h3>
      <ul class="reads"><li v-for="r in g.reads" :key="r">{{ r }}</li></ul>
      <p class="subtext">The device becomes a host of its own: findings, a row on the overview, read every 6 hours. vulnwatch only reads; it never
        changes anything on the device and the device never connects to vulnwatch.</p>
    </section>

    <section>
      <h3>Before you start, on the {{ g.title }}</h3>
      <ol class="prep"><li v-for="(s, i) in g.steps" :key="i" v-html="s" /></ol>
    </section>

    <form class="settings-form" @submit.prevent="save">
      <h3>Connection</h3>
      <div class="grid">
        <label><span class="field-label">Name (as host)</span><input v-model="form.name" name="appliance_name" autocomplete="off" required /></label>
        <label><span class="field-label">URL</span><input v-model="form.url" name="appliance_url" :placeholder="g.url" autocomplete="off" required /></label>
        <label v-if="g.account"><span class="field-label">{{ g.account }}</span><input v-model="form.account" name="appliance_account" autocomplete="off" required /></label>
        <SecretField v-model="form.token" name="appliance_token" :label="g.secret" :set="!!entry?.token?.set" :required="!entry" />
      </div>
      <p class="subtext">Over HTTPS vulnwatch pins the certificate it sees now and sends the {{ g.secret.toLowerCase() }} only to that certificate.
        The {{ g.secret.toLowerCase() }} is stored encrypted and never shown again.</p>
      <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
      <div class="actions">
        <button class="primary" :disabled="busy || !form.name || !form.url || (g.account && !form.account) || (!entry && !form.token)">
          <Icon name="check" :size="15" />{{ busy ? 'Connecting…' : entry ? 'Save and test' : 'Add and test' }}</button>
      </div>
    </form>

    <details class="api">
      <summary>API specification: what vulnwatch calls</summary>
      <table>
        <tr v-for="[k, v] in g.api" :key="k"><th>{{ k }}</th><td class="mono" v-html="v" /></tr>
      </table>
      <p class="subtext">Full description, with how findings are rated: <span class="mono">docs/INTEGRATIONS.md</span> → “Devices without agent”.</p>
    </details>
  </div>
</template>

<style scoped>
.guide { display: flex; flex-direction: column; gap: 1rem; }
h3 { font-size: 0.8125rem; margin: 0 0 0.5rem; }
.reads, .prep { margin: 0; padding-left: 1.25rem; font-size: 0.8125rem; line-height: 1.55; color: var(--text-2); }
.prep li + li, .reads li + li { margin-top: 0.25rem; }
.api summary { cursor: pointer; font-size: 0.8125rem; color: var(--text-2); }
.api table { margin-top: 0.5rem; border-collapse: collapse; font-size: 0.75rem; }
.api th { text-align: left; font-weight: 500; color: var(--muted); padding: 0.25rem 1rem 0.25rem 0; vertical-align: top; white-space: nowrap; }
.api td { padding: 0.25rem 0; overflow-wrap: anywhere; }
</style>
