<script setup>
import Icon from './Icon.vue'

// Eingeklappter Teil einer Einstellungskarte (Verbindungsformular, Feinabstimmung, lange Liste).
// Der Titel sagt, was drin ist; der Hinweis rechts fasst den Inhalt zusammen, damit man nicht aufklappen muss.
defineProps({
  title: { type: String, required: true },
  hint: { type: String, default: '' },
  open: { type: Boolean, default: false },
})
</script>

<template>
  <details class="settings-fold" :open="open || undefined">
    <summary>
      <Icon name="chevron" :size="14" class="chev" />
      <span class="fold-title">{{ title }}</span>
      <span v-if="hint || $slots.hint" class="fold-hint"><slot name="hint">{{ hint }}</slot></span>
    </summary>
    <div class="fold-body"><slot /></div>
  </details>
</template>

<style scoped>
.settings-fold { min-width: 0; }
summary {
  display: flex; align-items: baseline; gap: 0.5rem; width: fit-content; max-width: 100%; cursor: pointer; list-style: none;
  font-size: 0.8125rem; color: var(--text-2); border-radius: 6px;
}
summary::-webkit-details-marker { display: none; }
summary:hover .fold-title { color: var(--text); text-decoration: underline; text-underline-offset: 3px; text-decoration-color: var(--line-strong); }
summary:focus-visible { outline: 2px solid var(--text-2); outline-offset: 3px; }
.chev { align-self: center; flex: none; color: var(--muted); transition: transform 0.2s var(--ease); }
.settings-fold[open] > summary .chev { transform: rotate(90deg); }
.fold-title { font-weight: 500; }
.fold-hint { color: var(--muted); font-size: 0.75rem; }
.fold-body { display: flex; flex-direction: column; gap: 0.75rem; padding: 0.75rem 0 0.125rem 1.25rem; }
@media (prefers-reduced-motion: reduce) { .chev { transition: none; } }
</style>
