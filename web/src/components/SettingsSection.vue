<script setup>
// Abschnitt innerhalb einer Einstellungskarte: kleine Überschrift (optional mit Anzahl), Hinweis rechts, Inhalt
defineProps({
  title: { type: String, required: true },
  count: { type: Number, default: null },
  hint: { type: String, default: '' },
})
</script>

<template>
  <section class="settings-section">
    <header class="section-head">
      <h3>{{ title }}<span v-if="count != null" class="count">{{ count }}</span></h3>
      <span v-if="hint || $slots.aside" class="section-aside"><slot name="aside">{{ hint }}</slot></span>
    </header>
    <slot />
  </section>
</template>

<style scoped>
.settings-section { display: flex; flex-direction: column; gap: 0.6rem; }
.section-head { display: flex; justify-content: space-between; align-items: baseline; gap: 0.5rem 1rem; flex-wrap: wrap; }
h3 { margin: 0; font-size: 0.72rem; font-weight: 600; letter-spacing: 0.09em; text-transform: uppercase; color: var(--text-2); }
.count { margin-left: 0.5rem; font: 0.72rem var(--mono); color: var(--muted); letter-spacing: 0; }
.section-aside { font-size: 0.78rem; color: var(--muted); }
</style>
