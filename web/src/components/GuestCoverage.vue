<script setup>
import { ref } from 'vue'
import { api } from '../api.js'

// Proxmox-Gäste in der Abdeckung (PLAN-extensions D1): ohne Agent eine Lücke; gestoppte oder bewusste Ausnahmen
// mit Grund und Datum ausnehmen, wie bei Hosts (höchstens 180 Tage)
const props = defineProps({ guests: { type: Array, required: true } })
const emit = defineEmits(['changed'])

const STATUS = { ok: ['OK', 'badge ok'], fehler: ['GAP', 'badge danger'], excluded: ['EXCLUDED', 'badge neutral'] }
const isoDay = (days) => new Date(Date.now() + days * 86400000).toISOString().slice(0, 10)
const open = ref(null)   // subject des Gasts, dessen Formular offen ist
const form = ref({ until: '', reason: '' })
const busy = ref(false)
const error = ref('')

function startExclude(g) {
  form.value = { until: isoDay(30), reason: g.detail.startsWith('stopped') ? 'stopped guest' : '' }
  open.value = g.subject
  error.value = ''
}

async function run(fn) {
  busy.value = true
  error.value = ''
  try {
    await fn()
    open.value = null
    emit('changed')
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}
const submit = (g) => run(() => api.post('/api/coverage/exclusions', { subject: g.subject, ...form.value }))
const includeAgain = (g) => run(() => api.del(`/api/coverage/exclusions/${g.exclusion_id}`))
</script>

<template>
  <div class="table-wrap" data-test="guest-coverage">
    <table class="data-table">
      <thead><tr><th>Proxmox guest</th><th>Status</th><th class="text-right">Actions</th></tr></thead>
      <tbody>
        <template v-for="g in props.guests" :key="g.subject">
          <tr>
            <td class="strong">{{ g.name }}<span class="subtext">{{ g.type === 'lxc' ? 'LXC' : 'VM' }} {{ g.vmid }} on {{ g.node }} · {{ g.source }}</span></td>
            <td>
              <span :class="STATUS[g.status]?.[1] || 'badge neutral'">{{ STATUS[g.status]?.[0] || g.status }}</span>
              <span class="subtext truncate" :title="g.detail">{{ g.detail }}</span>
            </td>
            <td class="text-right">
              <button v-if="g.status === 'fehler' && open !== g.subject" class="btn-sm" data-test="guest-exclude" @click="startExclude(g)">Exclude…</button>
              <button v-if="g.status === 'excluded'" class="btn-sm" :disabled="busy" @click="includeAgain(g)">Include again</button>
            </td>
          </tr>
          <tr v-if="open === g.subject">
            <td colspan="3">
              <form class="exclude" data-test="guest-exclude-form" @submit.prevent="submit(g)">
                <label>Until <input v-model="form.until" type="date" name="guest_until" required :min="isoDay(1)" :max="isoDay(180)" /></label>
                <label>Reason <input v-model="form.reason" name="guest_reason" required minlength="3" maxlength="500" placeholder="e.g. stopped test VM" /></label>
                <div class="actions">
                  <button class="primary btn-sm" :disabled="busy">Exclude</button>
                  <button type="button" class="btn-sm" @click="open = null">Cancel</button>
                </div>
              </form>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
    <p v-if="error" class="error-text">{{ error }}</p>
  </div>
</template>

<style scoped>
.subtext { display: block; }
.exclude { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: flex-end; }
.exclude label { display: flex; flex-direction: column; gap: 0.25rem; }
.exclude .actions { display: flex; gap: 0.5rem; }
.error-text { color: var(--danger, #c0392b); }
</style>
