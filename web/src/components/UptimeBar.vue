<script setup>
import { STATE, fmtPct } from '../health.js'

// Verfügbarkeit als Balkenreihe (älteste links): je Abschnitt der schlechteste Zustand, Verfügbarkeit im Tooltip
defineProps({
  segments: { type: Array, required: true },   // [{ state, uptime }]
  label: { type: String, default: 'Availability' },
  start: { type: String, default: '' },
  end: { type: String, default: 'now' },
  compact: { type: Boolean, default: false },
})
const title = (s) => `${(STATE[s.state] || STATE.unknown).label}${s.uptime != null ? ` · ${fmtPct(s.uptime)} up` : ''}`
</script>

<template>
  <div :class="['uptime-bar', { compact }]">
    <div class="bars" role="img" :aria-label="label">
      <i v-for="(s, i) in segments" :key="i" :class="['cell', s.state]" :title="title(s)" />
    </div>
    <div v-if="!compact && start" class="axis" aria-hidden="true"><span>{{ start }}</span><span>{{ end }}</span></div>
  </div>
</template>

<style scoped>
.uptime-bar { display: flex; flex-direction: column; gap: 0.3rem; min-width: 0; }
.bars { display: flex; gap: 2px; height: 26px; align-items: stretch; }
.compact .bars { height: 18px; gap: 1px; }
.cell { flex: 1; min-width: 2px; border-radius: 2px; background: var(--surface-3); }
.cell.up { background: var(--ok); }
.cell.degraded { background: var(--warn); }
.cell.down { background: var(--danger); }
.cell.unknown, .cell.paused { background: var(--surface-3); }
.cell:hover { filter: brightness(1.25); }
.axis { display: flex; justify-content: space-between; font: 0.68rem var(--mono); color: var(--muted); }
</style>
