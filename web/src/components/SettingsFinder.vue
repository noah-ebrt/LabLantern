<script setup>
import { computed, ref, useId } from 'vue'
import Icon from './Icon.vue'
import { SETTINGS_TABS, findSettings } from '../settingsIndex.js'

// „Find a setting“: Treffer aus dem Index der Einstellungen; Auswahl wechselt den Reiter und springt zur Stelle
const emit = defineEmits(['go'])
const q = ref('')
const open = ref(false)
const cursor = ref(0)
const uid = useId()
const hits = computed(() => findSettings(q.value).slice(0, 8))
const tabLabel = (key) => SETTINGS_TABS.find((t) => t.key === key)?.label

function pick(hit) {
  emit('go', hit)
  q.value = ''
  open.value = false
}

function onKey(e) {
  const last = hits.value.length - 1
  if (e.key === 'ArrowDown') { e.preventDefault(); open.value = true; cursor.value = Math.min(cursor.value + 1, last) }
  else if (e.key === 'ArrowUp') { e.preventDefault(); cursor.value = Math.max(cursor.value - 1, 0) }
  else if (e.key === 'Enter') { e.preventDefault(); if (hits.value[cursor.value]) pick(hits.value[cursor.value]) }
  else if (e.key === 'Escape') { open.value = false }
}

function onInput() {
  open.value = true
  cursor.value = 0
}

// Fokus verlässt das Feld samt Liste: Liste schließen
function onFocusOut(e) {
  if (!e.currentTarget.contains(e.relatedTarget)) open.value = false
}
</script>

<template>
  <div class="finder" @focusout="onFocusOut">
    <Icon name="search" :size="14" class="finder-icon" />
    <input v-model="q" type="search" role="combobox" aria-label="Find a setting" placeholder="Find a setting…" autocomplete="off"
           aria-autocomplete="list" :aria-expanded="open && hits.length > 0" :aria-controls="`${uid}-hits`"
           :aria-activedescendant="open && hits.length ? `${uid}-hit-${cursor}` : undefined"
           data-test="settings-finder" @input="onInput" @focus="open = !!q" @keydown="onKey" />
    <ul v-show="open && hits.length" :id="`${uid}-hits`" role="listbox" class="hits" aria-label="Matching settings">
      <li v-for="(h, i) in hits" :id="`${uid}-hit-${i}`" :key="h.target + h.label" role="option" :aria-selected="i === cursor"
          :class="{ active: i === cursor }" @mousedown.prevent="pick(h)" @mousemove="cursor = i">
        <span class="hit-label">{{ h.label }}</span>
        <span class="hit-where">{{ tabLabel(h.tab) }}</span>
      </li>
    </ul>
    <p v-if="open && q.trim() && !hits.length" class="no-hit" role="status">No setting matches “{{ q.trim() }}”.</p>
  </div>
</template>

<style scoped>
.finder { position: relative; width: min(100%, 300px); }
.finder-icon { position: absolute; left: 0.75rem; top: 50%; transform: translateY(-50%); color: var(--muted); pointer-events: none; }
.finder input { width: 100%; min-height: 36px; padding-left: 2.1rem; font-size: 0.86rem; border-radius: var(--radius-pill); }
.hits, .no-hit {
  position: absolute; z-index: 20; top: calc(100% + 6px); left: 0; right: 0; margin: 0;
  background: var(--surface-2); border: 1px solid var(--line-strong); border-radius: var(--radius-sm);
  box-shadow: 0 12px 32px -8px rgba(0, 0, 0, 0.6);
}
.hits { list-style: none; padding: 0.3rem; max-height: 22rem; overflow-y: auto; }
.hits li { display: flex; justify-content: space-between; align-items: baseline; gap: 0.75rem; padding: 0.45rem 0.6rem; border-radius: 6px; cursor: pointer; }
.hits li.active { background: var(--surface-3); }
.hit-label { color: var(--text); font-size: 0.86rem; }
.hit-where { color: var(--muted); font-size: 0.75rem; white-space: nowrap; }
.no-hit { padding: 0.6rem 0.75rem; font-size: 0.82rem; color: var(--muted); }
@media (max-width: 640px) { .finder { width: 100%; } }
</style>
