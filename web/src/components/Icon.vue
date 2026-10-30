<script setup>
// Kleine, einheitliche Strich-Icons (24er Raster, 1.75 px), angelehnt an Lucide (ISC).
defineProps({ name: { type: String, required: true }, size: { type: Number, default: 16 } })

const PATHS = {
  overview: ['M3 3h7v9H3z', 'M14 3h7v5h-7z', 'M14 12h7v9h-7z', 'M3 16h7v5H3z'],
  findings: ['M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z', 'M12 8v5', 'M12 16.5v.01'],
  systems: ['M3 4h18v6H3z', 'M3 14h18v6H3z', 'M7 7h.01', 'M7 17h.01'],
  runs: ['M3 12a9 9 0 1 0 3-6.7L3 8', 'M3 3v5h5', 'M12 7v5l3 2'],
  settings: ['M4 6h10', 'M18 6h2', 'M4 12h4', 'M12 12h8', 'M4 18h12', 'M20 18h0', 'M16 4v4', 'M10 10v4', 'M18 16v4'],
  search: ['M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z', 'M20 20l-4-4'],
  logout: ['M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4', 'M16 17l5-5-5-5', 'M21 12H9'],
  play: ['M7 4v16l13-8z'],
  menu: ['M4 6h16', 'M4 12h16', 'M4 18h16'],
  external: ['M14 4h6v6', 'M20 4l-9 9', 'M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5'],
  refresh: ['M20 11a8 8 0 0 0-14.9-3L3 10', 'M3 4v6h6', 'M4 13a8 8 0 0 0 14.9 3L21 14', 'M21 20v-6h-6'],
  chevron: ['M9 6l6 6-6 6'],
  plus: ['M12 5v14', 'M5 12h14'],
  shield: ['M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z', 'M9 12l2 2 4-4'],
  bell: ['M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9', 'M13.73 21a2 2 0 0 1-3.46 0'],
  mail: ['M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z', 'M22 6l-10 7L2 6'],
  clock: ['M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z', 'M12 6v6l4 2'],
  trash: ['M3 6h18', 'M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6', 'M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2'],
  check: ['M20 6L9 17l-5-5'],
  copy: ['M9 9h11v11H9z', 'M5 15H4V4h11v1'],
  key: ['M7.5 10a5.5 5.5 0 1 0 0 11 5.5 5.5 0 0 0 0-11z', 'M21 2l-9.6 9.6', 'M15.5 7.5l2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4'],
  activity: ['M22 12h-4l-3 9L9 3l-3 9H2'],
  lock: ['M5 11h14v10H5z', 'M8 11V7a4 4 0 0 1 8 0v4'],
  link: ['M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1', 'M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1'],
  download: ['M12 4v11', 'M7 10l5 5 5-5', 'M4 20h16'],
  sparkles: ['M12 3l2.5 5 5 2.5-5 2.5-2.5 5-2.5-5-5-2.5 5-2.5z'],
  package: ['M16.5 9.4L7.55 4.24', 'M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z', 'M3.27 6.96L12 12.01l8.73-5.05', 'M12 22.08V12'],
  x: ['M18 6L6 18', 'M6 6l12 12'],
}
</script>

<template>
  <svg :width="size" :height="size" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"
       stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path v-for="(d, i) in PATHS[name]" :key="i" :d="d" />
  </svg>
</template>
