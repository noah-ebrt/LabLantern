<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { useLive } from '../live.js'
import { timeAgo } from '../time.js'
import Icon from './Icon.vue'
import SettingsCard from './SettingsCard.vue'
import SettingsEntry from './SettingsEntry.vue'
import SettingsList from './SettingsList.vue'
import SettingsFold from './SettingsFold.vue'

// Produktstände: Registry-Digest je laufendem Image, neuere Versionen, Release-Linien von endoflife.date
const versions = ref(null)
const systems = ref([])
const message = ref(null)

async function load() {
  const [v, s] = await Promise.all([api.get('/api/versions'), api.get('/api/systems')])
  versions.value = v
  systems.value = s
}

const totals = computed(() => {
  const out = { current: 0, outdated: 0, 'newer-version': 0, unknown: 0, pending: 0, local: 0 }
  for (const s of Object.values(versions.value?.systems || {})) for (const r of s.rows) out[r.status] = (out[r.status] || 0) + 1
  return out
})

// Veraltete und nicht prüfbare Images je Host: Ziel des Status-Badges der Karte
const problems = computed(() => Object.entries(versions.value?.systems || {}).flatMap(([sid, s]) =>
  s.rows.filter((r) => r.status === 'outdated' || r.status === 'unknown').map((r) => ({ ...r, system: sysName(sid) })))
  .sort((a, b) => (a.status === b.status ? 0 : a.status === 'unknown' ? -1 : 1)))

// Nur Zahlen über null; „0 newer version · 0 queued“ sagt nichts
const counts = computed(() => {
  const t = totals.value
  return [[t.current, 'current'], [t.outdated, 'outdated'], [t['newer-version'], 'newer version available'],
    [t.unknown, 'not checkable'], [t.pending, 'queued (Docker Hub limit)'], [t.local, 'built locally']]
    .filter(([n]) => n).map(([n, l]) => `${n} ${l}`).join(' · ')
})

async function checkNow() {
  await api.post('/api/versions/refresh')
  message.value = { kind: 'ok', text: 'Version check started. Results appear here and on each host in a minute or two.' }
  setTimeout(load, 15000)
}

const status = computed(() => {
  if (!versions.value?.at) return { tone: 'neutral', text: 'Not checked yet' }
  const t = totals.value
  if (!t.unknown && !t.outdated) return { tone: 'ok', text: 'All current' }
  return { tone: t.unknown ? 'danger' : 'warning', text: `${t.outdated} outdated · ${t.unknown} not checkable`,
           target: problems.value.length ? 'version-problems' : null }
})

const sysName = (id) => systems.value.find((s) => s.id === Number(id))?.name || `#${id}`
onMounted(load)
useLive(['settings', 'findings'], load, 3000)
</script>

<template>
  <SettingsCard icon="package" title="Version check" subtitle="Finds outdated images and end-of-life releases on every host, every 6 hours" :status="status">
    <SettingsList>
      <SettingsEntry icon="refresh" title="Registry and end-of-life check" class="version-entry"
                     :meta="[versions?.at ? `Last pass ${timeAgo(new Date(versions.at * 1000).toISOString())}` : 'Not run yet', versions?.at ? counts : '']">
        <template #actions>
          <button type="button" class="btn-sm" @click="checkNow"><Icon name="refresh" :size="14" />Check now</button>
        </template>
        <span class="subtext">Compares each running image with its registry and each release line with endoflife.date.
          Results show up as <RouterLink :to="{ path: '/funde', query: { source: 'products' } }">Versions &amp; EOL findings</RouterLink>,
          in the overview's Versions column and per container on each host.</span>
        <p v-if="versions?.eol_error" class="message error">{{ versions.eol_error }}</p>
        <SettingsFold v-if="problems.length" id="version-problems" data-test="version-problems" title="Which images"
                      :hint="`${totals.outdated} outdated · ${totals.unknown} not checkable`">
          <div>
            <span v-for="p in problems" :key="p.system + p.image + p.containers.join()" class="more-line">
              <span :class="['days', p.status === 'unknown' ? 'danger' : 'warning']">{{ p.status === 'unknown' ? 'not checkable' : 'outdated' }}</span>
              · {{ p.system }} · <span class="mono">{{ p.image || p.containers.join(', ') }}</span>{{ p.detail ? ` · ${p.detail}` : '' }}
            </span>
          </div>
        </SettingsFold>
      </SettingsEntry>
    </SettingsList>
    <p v-if="message" class="message" :class="message.kind" role="status">{{ message.text }}</p>
  </SettingsCard>
</template>

<style scoped>
.more-line { display: block; font-size: 0.75rem; color: var(--muted); padding: 0.125rem 0; overflow-wrap: anywhere; }
.more-line .mono { color: var(--text-2); }
.days { font: 0.75rem var(--mono); font-variant-numeric: tabular-nums; white-space: nowrap; }
.days.warning { color: var(--med); }
.days.danger { color: var(--crit); font-weight: 600; }
.version-entry .subtext a { color: var(--text-2); }
</style>
