<script setup>
// Bildmarke: Vorhängeschloss-Laterne (64er Raster). Körper in currentColor, Fenster bernsteinfarben, Schlüsselloch dunkel.
// Unter 24 px ohne Schlitz im Schlüsselloch, der würde nur verschwimmen. Gleiche Form wie docs/media/lablantern-logo.svg
// und die Icons in public/.
defineProps({ size: { type: Number, default: 32 } })
</script>

<template>
  <svg :width="size" :height="size" viewBox="0 0 64 64" role="img" aria-label="LabLantern">
    <g transform="translate(0,0.5)">
      <path d="M23.5 26V16.5a8.5 8.5 0 0 1 17 0V26" fill="none" stroke="currentColor" :stroke-width="size < 24 ? 6.5 : 5.5" stroke-linecap="round" />
      <rect x="15" y="24" width="34" height="6" rx="3" fill="currentColor" />
      <path d="M17 29h30v11.5c0 8.5-6 14.3-15 17.5-9-3.2-15-9-15-17.5z" fill="currentColor" />
      <path d="M22.5 33.5h19v7c0 5.6-3.8 9.6-9.5 11.8-5.7-2.2-9.5-6.2-9.5-11.8z" fill="#f5a524" />
      <circle cx="32" cy="40" r="3.2" fill="#15171e" />
      <path v-if="size >= 24" d="M30.5 41.8h3l1 6h-5z" fill="#15171e" />
    </g>
  </svg>
</template>
