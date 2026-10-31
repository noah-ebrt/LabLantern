<script setup>
import { computed } from 'vue'
import { DISK_TYPE, STATE_TEXT, fmtBytes, groups } from '../storage.js'

// Pools und Laufwerke eines NAS (TrueNAS, Synology, Proxmox) nebeneinander: je Laufwerk ein Symbol in der Farbe
// seines Zustands, Einzelheiten beim Darüberfahren oder Fokussieren.
const props = defineProps({ storage: { type: Object, required: true } })

const rows = computed(() => groups(props.storage))
const label = (d) => [d.name, d.model, fmtBytes(d.size), DISK_TYPE[d.type], d.temp != null ? `${d.temp} °C` : '',
  STATE_TEXT[d.state] + (d.status && d.state !== 'ok' ? ` (${d.status})` : '')].filter(Boolean).join(' · ')
const barTone = (p) => (p >= 95 ? 'bad' : p >= 90 ? 'warn' : 'ok')
</script>

<template>
  <div class="storage" data-test="storage">
    <div v-for="g in rows" :key="g.kind + g.name" class="pool" :data-test="`pool-${g.name}`">
      <div class="pool-head">
        <span :class="['pool-name', { subtext: g.loose }]">{{ g.name }}</span>
        <span v-if="g.layout" class="chip mono">{{ g.layout }}</span>
        <span v-if="g.state && g.state !== 'ok'" :class="['badge', g.state === 'bad' ? 'danger' : g.state === 'warn' ? 'warning' : 'neutral']">
          {{ g.status || STATE_TEXT[g.state] }}</span>
        <span v-if="g.percent != null" class="usage" :title="`${g.kind} · ${g.percent} % used${g.size ? ` of ${fmtBytes(g.size)}` : ''}`">
          <span class="bar"><span :class="['fill', barTone(g.percent)]" :style="{ width: `${Math.min(100, g.percent)}%` }" /></span>
          <span class="subtext">{{ Math.round(g.percent) }} %</span>
        </span>
      </div>
      <ul v-if="g.members.length" class="disks">
        <li v-for="d in g.members" :key="d.name" :class="['disk', d.state, d.type || 'hdd']" tabindex="0" :aria-label="label(d)" :data-test="`disk-${d.name}`">
          <svg v-if="d.type === 'nvme'" class="icon" viewBox="0 0 32 30" aria-hidden="true">
            <rect x="1.5" y="15.5" width="29" height="12" rx="1.5" />
            <rect x="5.5" y="18.5" width="7" height="6" rx="0.6" class="part" /><rect x="14.5" y="18.5" width="7" height="6" rx="0.6" class="part" />
            <path d="M25 19v5M27.5 19v5" />
          </svg>
          <svg v-else-if="d.type === 'ssd'" class="icon" viewBox="0 0 24 30" aria-hidden="true">
            <rect x="2.5" y="2.5" width="19" height="25" rx="2.5" />
            <rect x="6.5" y="7" width="11" height="8" rx="1" class="part" /><path d="M7 20h10M7 23h6" />
          </svg>
          <svg v-else class="icon" viewBox="0 0 24 30" aria-hidden="true">
            <rect x="2.5" y="2.5" width="19" height="25" rx="2.5" />
            <circle cx="12" cy="12.5" r="6" /><circle cx="12" cy="12.5" r="1.4" class="part" /><path d="M17 23.5l-4-9" />
          </svg>
          <i v-if="d.state === 'bad' || d.state === 'warn'" class="dot" />
          <span class="tip" role="tooltip">
            <strong>{{ d.name }}</strong>
            <span v-if="d.model">{{ d.model }}</span>
            <span>{{ [fmtBytes(d.size), DISK_TYPE[d.type], d.temp != null ? `${d.temp} °C` : ''].filter(Boolean).join(' · ') }}</span>
            <span :class="['state-text', d.state]">{{ STATE_TEXT[d.state] }}{{ d.status && d.state !== 'ok' ? ` (${d.status})` : '' }}</span>
            <span v-if="d.detail" class="subtext">{{ d.detail }}</span>
          </span>
        </li>
      </ul>
    </div>
    <p v-if="storage.error" class="subtext error">{{ storage.error }}</p>
  </div>
</template>

<style scoped>
.storage { display: flex; flex-wrap: wrap; gap: 0.75rem 1.75rem; padding: 0.25rem 0 1rem; }
.pool { display: flex; flex-direction: column; gap: 0.3rem; min-width: 0; }
.pool-head { display: flex; align-items: center; flex-wrap: wrap; gap: 0.4rem; font-size: 0.78rem; }
.pool-name { font-weight: 500; }
.chip { font-size: 0.68rem; padding: 0.05rem 0.4rem; border: 1px solid var(--line-strong); border-radius: 999px; color: var(--text-2); }
.usage { display: inline-flex; align-items: center; gap: 0.4rem; }
.bar { width: 4.5rem; height: 0.3rem; border-radius: 999px; background: var(--line-strong); overflow: hidden; }
.fill { display: block; height: 100%; border-radius: inherit; background: var(--ok); }
.fill.warn { background: var(--med); }
.fill.bad { background: var(--crit); }
.disks { display: flex; flex-wrap: wrap; gap: 0.3rem; list-style: none; margin: 0; padding: 0; }
.disk { position: relative; display: flex; color: var(--ok); border-radius: 4px; outline-offset: 2px; cursor: default; }
.disk.warn { color: var(--med); }
.disk.bad { color: var(--crit); }
.disk.unknown { color: var(--muted); }
.icon { width: 1.1rem; height: 1.35rem; fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round;
  transition: transform 0.15s ease; }
.disk.nvme .icon { width: 1.5rem; }
.icon .part { fill: currentColor; fill-opacity: 0.25; }
.disk.bad .icon > rect:first-of-type { fill: currentColor; fill-opacity: 0.12; }
.disk.unknown .icon { stroke-dasharray: 2.5 2; }
.disk:hover .icon, .disk:focus-visible .icon { transform: translateY(-2px); }
.dot { position: absolute; top: -2px; right: -3px; width: 0.4rem; height: 0.4rem; border-radius: 50%; background: currentColor;
  box-shadow: 0 0 0 2px var(--surface); }
/* Unter dem Symbol und an seiner linken Kante: zentriert ragte es bei Laufwerken am linken Rand aus dem Dialog */
.tip { display: none; position: absolute; z-index: 20; top: calc(100% + 6px); left: -0.25rem;
  flex-direction: column; gap: 0.1rem; min-width: 11rem; max-width: 16rem; padding: 0.45rem 0.6rem; border-radius: 8px;
  background: var(--surface-2); border: 1px solid var(--line-strong); color: var(--text-2); font-size: 0.75rem;
  line-height: 1.35; text-align: left; overflow-wrap: anywhere; box-shadow: 0 6px 18px rgba(0, 0, 0, 0.35); pointer-events: none; }
.tip strong { color: var(--text); }
.disk:hover .tip, .disk:focus-visible .tip { display: flex; }
.state-text.ok { color: var(--ok); }
.state-text.warn { color: var(--med); }
.state-text.bad { color: var(--crit); }
.state-text.unknown { color: var(--muted); }
.error { flex-basis: 100%; margin: 0; }
@media (prefers-reduced-motion: reduce) { .icon { transition: none; } }
</style>
