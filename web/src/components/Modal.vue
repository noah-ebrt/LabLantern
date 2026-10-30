<script setup>
import { nextTick, onBeforeUnmount, onMounted, ref } from 'vue'

// Grundgerüst aller Dialoge: Hintergrund, Escape und Klick daneben schließen, Fokus hinein und wieder zurück,
// Aktionen unten rechts mit "Close" am Ende (footer=false, wenn der Dialog eigene Knöpfe hat, z. B. in einem Formular)
defineProps({
  label: { type: String, default: '' },
  size: { type: String, default: '' },        // 'lg' für breite Dialoge
  footer: { type: Boolean, default: true },
})
const emit = defineEmits(['close'])

const box = ref(null)
let before = null
const onKey = (e) => {
  if (e.key === 'Escape') emit('close')
}
onMounted(async () => {
  before = document.activeElement
  document.addEventListener('keydown', onKey)
  await nextTick()
  box.value?.focus()
})
onBeforeUnmount(() => {
  document.removeEventListener('keydown', onKey)
  before?.focus?.()
})
</script>

<template>
  <div class="modal-backdrop" @click.self="emit('close')">
    <div ref="box" :class="['modal', size && `modal-${size}`]" role="dialog" aria-modal="true" :aria-label="label" tabindex="-1">
      <slot />
      <div v-if="footer" class="modal-actions">
        <slot name="actions" />
        <button type="button" class="secondary" @click="emit('close')">Close</button>
      </div>
    </div>
  </div>
</template>
