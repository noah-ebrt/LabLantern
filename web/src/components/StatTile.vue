<script setup>
// Kennzahl als Kachel: Bezeichnung, großer Wert, Hinweis darunter; `tone` färbt einen Akzentpunkt
defineProps({
  label: { type: String, required: true },
  value: { type: [String, Number], required: true },
  hint: { type: String, default: '' },
  tone: { type: String, default: '' },   // ok | warning | danger | neutral
})
</script>

<template>
  <div :class="['stat-tile', tone]">
    <span class="stat-label"><i v-if="tone" class="dot" aria-hidden="true" />{{ label }}</span>
    <strong class="stat-value">{{ value }}</strong>
    <span v-if="hint || $slots.default" class="stat-hint"><slot>{{ hint }}</slot></span>
  </div>
</template>

<style scoped>
.stat-tile {
  display: flex; flex-direction: column; gap: 0.25rem; padding: 1rem; min-width: 0;
  background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius);
}
.stat-label { display: flex; align-items: center; gap: 0.5rem; font-size: 0.75rem; color: var(--muted); }
.dot { width: 7px; height: 7px; border-radius: 50%; background: var(--line-strong); }
.ok .dot { background: var(--ok); }
.warning .dot { background: var(--warn); }
.danger .dot { background: var(--danger); }
.stat-value { font-size: 1.5rem; font-weight: 600; font-variant-numeric: tabular-nums; color: var(--text); line-height: 1.1; }
.danger .stat-value { color: var(--danger); }
.stat-hint { font-size: 0.75rem; color: var(--muted); }
</style>
