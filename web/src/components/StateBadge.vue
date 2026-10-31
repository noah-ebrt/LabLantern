<script setup>
import { computed } from 'vue'
import { stateOf } from '../health.js'

// Zustand eines Monitors oder einer Prüfung als Abzeichen (up, degraded, down, unknown, paused)
const props = defineProps({ state: { type: String, default: 'unknown' }, stale: { type: Boolean, default: false } })
const meta = computed(() => stateOf(props.state))
</script>

<template>
  <span :class="['badge', meta.tone]" :title="stale ? 'Result too old – shown as unknown' : undefined">{{ meta.label }}{{ stale ? ' · stale' : '' }}</span>
</template>
