<script setup>
import { fmtDateTime } from '../time.js'
import Icon from './Icon.vue'

// Eingabe für ein Geheimnis: wird nur geschrieben, nie wieder angezeigt. Unter dem Feld steht, ob einer
// gespeichert ist und seit wann. Leer lassen = gespeicherten Wert behalten.
const model = defineModel({ type: String, default: '' })
defineProps({
  label: { type: String, required: true },
  name: { type: String, required: true },
  set: { type: Boolean, default: false },
  updatedAt: { type: String, default: null },
  placeholder: { type: String, default: '' },
  required: { type: Boolean, default: false },
  help: { type: String, default: '' },
  state: { type: Boolean, default: true },   // aus, wenn ein Eintrag darüber den gespeicherten Zustand schon nennt
})
</script>

<template>
  <label class="secret-field">
    <span class="field-label">{{ label }}</span>
    <input v-model="model" :name="name" type="password" autocomplete="new-password" spellcheck="false"
           :required="required && !set" :placeholder="set ? 'Stored – type a new value to replace it' : placeholder" />
    <span v-if="state" :class="['secret-state', { set }]">
      <Icon :name="set ? 'lock' : 'x'" :size="13" />
      <template v-if="set">Stored encrypted{{ updatedAt ? ` · changed ${fmtDateTime(updatedAt)}` : '' }}</template>
      <template v-else>Not set</template>
    </span>
    <span v-if="help" class="subtext">{{ help }}</span>
  </label>
</template>

<style scoped>
.secret-field { display: flex; flex-direction: column; gap: 0.25rem; }
.secret-state { display: inline-flex; align-items: center; gap: 0.25rem; }
</style>
