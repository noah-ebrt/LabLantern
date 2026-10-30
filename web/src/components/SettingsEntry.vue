<script setup>
import Icon from './Icon.vue'

// Ein konfigurierter Eintrag (Kanal, Passkey, Schlüssel, Prüfung, Verbindung): Symbol, Name, Angaben,
// Status rechts, Aktionen rechts. Weitere Inhalte (z. B. ein Eingabefeld) kommen in den Standard-Slot.
defineProps({
  icon: { type: String, default: '' },
  title: { type: String, required: true },
  meta: { type: [String, Array], default: '' },   // eine Zeile oder mehrere
  mono: { type: Boolean, default: false },         // Titel ist ein Wert (Domain, Version), keine Bezeichnung
  dense: { type: Boolean, default: false },        // eine Zeile, für lange Listen gleichartiger Werte
})
</script>

<template>
  <li :class="['settings-entry', { dense }]">
    <span v-if="icon" class="entry-icon" aria-hidden="true"><Icon :name="icon" :size="16" /></span>
    <div class="entry-main">
      <div class="entry-title">
        <span :class="['name', { mono }]">{{ title }}</span>
        <slot name="badge" />
      </div>
      <template v-if="meta">
        <span v-for="(m, i) in [].concat(meta)" :key="i" class="entry-meta">{{ m }}</span>
      </template>
      <slot name="meta" />
    </div>
    <div v-if="$slots.actions" class="entry-actions"><slot name="actions" /></div>
    <div v-if="$slots.default" class="entry-body"><slot /></div>
  </li>
</template>

<style scoped>
.settings-entry {
  display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: center; gap: 0.35rem 0.85rem;
  padding: 0.8rem 0.95rem; border-top: 1px solid var(--line);
}
.settings-entry:first-child { border-top: 0; }
.settings-entry.dense { padding: 0.45rem 0.95rem; }
.settings-entry.dense .name.mono { font-size: 0.8rem; color: var(--text-2); }
.entry-icon {
  display: flex; align-items: center; justify-content: center; width: 32px; height: 32px; align-self: start;
  border-radius: 8px; background: var(--surface-2); border: 1px solid var(--line); color: var(--text-2);
}
.settings-entry:not(:has(.entry-icon)) { grid-template-columns: minmax(0, 1fr) auto; }
.entry-main { display: flex; flex-direction: column; gap: 0.15rem; min-width: 0; }
.entry-title { display: flex; align-items: center; gap: 0.55rem; flex-wrap: wrap; }
.name { color: var(--text); font-weight: 500; overflow-wrap: anywhere; }
.name.mono { font-family: var(--mono); font-size: 0.86rem; font-weight: 400; }
.entry-meta { font-size: 0.8rem; color: var(--muted); overflow-wrap: anywhere; }
.entry-actions { display: flex; align-items: center; gap: 0.45rem; flex-wrap: wrap; justify-content: flex-end; }
.entry-body { grid-column: 1 / -1; display: flex; flex-direction: column; gap: 0.5rem; }
.settings-entry:has(.entry-icon) .entry-body { grid-column: 2 / -1; }
@media (max-width: 640px) {
  .settings-entry { grid-template-columns: auto minmax(0, 1fr); }
  .entry-actions { grid-column: 1 / -1; justify-content: flex-start; }
  .settings-entry:has(.entry-icon) .entry-actions { grid-column: 2 / -1; }
}
</style>
