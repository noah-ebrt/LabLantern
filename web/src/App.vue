<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import Icon from './components/Icon.vue'
import Logo from './components/Logo.vue'
import { logout, session } from './session.js'
import { live, startLive, stopLive } from './live.js'

const router = useRouter()
const route = useRoute()
const navOpen = ref(false)
const search = ref('')
const searchInput = ref(null)

const NAV = [
  { group: 'Monitor', items: [
    { to: '/', label: 'Overview', icon: 'overview' },
    { to: '/gesundheit', label: 'Health', icon: 'activity' },
    { to: '/funde', label: 'Findings', icon: 'findings' },
    { to: '/fruehwarnungen', label: 'Early warnings', icon: 'sparkles' },
    { to: '/laeufe', label: 'Scan runs', icon: 'runs' },
    { to: '/verlauf', label: 'History', icon: 'clock' },
  ] },
  { group: 'Fleet', items: [{ to: '/systeme', label: 'Systems', icon: 'systems' }] },
  { group: 'Configuration', items: [{ to: '/einstellungen', label: 'Settings', icon: 'settings' }] },
]
const currentItem = computed(() => NAV.flatMap((g) => g.items).find((i) => i.to === route.path))
const current = computed(() => currentItem.value?.label ?? 'Dashboard')
const currentIcon = computed(() => currentItem.value?.icon ?? 'overview')

watch(() => route.fullPath, () => { navOpen.value = false })
watch(() => route.query.q, (q) => { search.value = q ?? '' }, { immediate: true })
// Eine Live-Verbindung, solange jemand angemeldet ist
watch(() => session.authenticated, (on) => (on ? startLive() : stopLive()), { immediate: true })

function submitSearch() {
  router.push({ path: '/funde', query: search.value.trim() ? { q: search.value.trim() } : {} })
}

function onKey(e) {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault()
    searchInput.value?.focus()
  }
}
onMounted(() => window.addEventListener('keydown', onKey))
onBeforeUnmount(() => window.removeEventListener('keydown', onKey))

async function doLogout() {
  await logout()
  router.push('/login')
}
</script>

<template>
  <div v-if="session.authenticated" class="shell" :class="{ 'nav-open': navOpen }">
    <aside class="sidebar">
      <div class="brand">
        <Logo  class="mark" :size="32" />
        <div>
          <span class="brand-name">LabLantern</span>
          <span class="brand-sub">Homelab Fleet</span>
        </div>
      </div>
      <nav>
        <div v-for="g in NAV" :key="g.group" class="nav-group">
          <span class="nav-heading">{{ g.group }}</span>
          <RouterLink v-for="i in g.items" :key="i.to" :to="i.to" class="nav-link">
            <Icon :name="i.icon" :size="16" />{{ i.label }}
          </RouterLink>
        </div>
      </nav>
      <div class="user-card">
        <span class="avatar">{{ (session.username || '?').slice(0, 1).toUpperCase() }}</span>
        <div class="user-meta">
          <span class="user-name">{{ session.username }}</span>
          <span class="user-role">Administrator</span>
        </div>
        <button class="icon-btn" title="Sign out" aria-label="Sign out" @click="doLogout"><Icon name="logout" :size="15" /></button>
      </div>
    </aside>
    <div class="scrim" @click="navOpen = false" />

    <div class="main-col">
      <header class="topbar">
        <div class="topbar-inner">
          <div class="topbar-left">
            <button class="icon-btn menu-btn" aria-label="Open navigation" @click="navOpen = true"><Icon name="menu" /></button>
            <nav class="crumbs" aria-label="Breadcrumb">
              <div class="crumb-pill">
                <Icon :name="currentIcon" :size="15" />
                <span class="crumb-title">{{ current }}</span>
              </div>
            </nav>
          </div>
          <span class="live-dot" :class="{ on: live.connected }" :title="live.connected ? 'Live updates connected' : 'Live updates reconnecting…'" role="status" :aria-label="live.connected ? 'Live' : 'Offline'"><span />{{ live.connected ? 'Live' : 'Offline' }}</span>
          <form class="search" role="search" @submit.prevent="submitSearch">
            <Icon name="search" :size="14" />
            <input ref="searchInput" v-model="search" type="search" placeholder="Search CVE, package, host…" aria-label="Search findings" />
            <kbd>Ctrl K</kbd>
          </form>
        </div>
      </header>
      <main>
        <RouterView />
      </main>
    </div>
  </div>
  <main v-else class="auth">
    <div class="auth-brand"><Logo class="mark" :size="56" />LabLantern</div>
    <RouterView />
  </main>
</template>

<style scoped>
.shell { display: grid; grid-template-columns: 248px minmax(0, 1fr); min-height: 100vh; }
.sidebar {
  position: sticky; top: 0; height: 100vh; display: flex; flex-direction: column; gap: 1.25rem;
  background: var(--sidebar); border-right: 1px solid var(--line); padding: 1rem;
}
.brand {
  display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem;
  border: 1px solid var(--line-strong); border-radius: var(--radius-sm); background: var(--surface);
}
.mark { flex: none; color: var(--text); 
    border: 1px #4c4c4c solid;
    border-radius: 5.4px;}
.brand-name { display: block; font-weight: 600; letter-spacing: -0.01em; color: var(--text); }
.brand-sub { display: block; font-size: 0.6875rem; color: var(--muted); }
nav { flex: 1; overflow-y: auto; }
.nav-group { display: flex; flex-direction: column; gap: 3px; margin-bottom: 1.25rem; }
.nav-heading { font-size: 0.6875rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); padding: 0 0.75rem 0.5rem; }
.nav-link {
  display: flex; align-items: center; gap: 0.75rem; padding: 0.5rem 0.75rem; border-radius: var(--radius-sm);
  color: var(--text-2); text-decoration: none; border: 1px solid transparent; transition: all 0.15s ease;
  font-size: 0.875rem; font-weight: 500;
}
.nav-link:hover { background: var(--surface-2); color: var(--text); }
.nav-link.router-link-exact-active {
  background: var(--surface-2);
  border-color: var(--line-strong);
  color: #ffffff;
  font-weight: 600;
}
.user-card {
  display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem;
  border: 1px solid var(--line); border-radius: var(--radius-sm); background: var(--surface);
}
.avatar { width: 32px; height: 32px; border-radius: 50%; display: grid; place-items: center; background: var(--surface-3); font-weight: 600; flex: none; }
.user-meta { flex: 1; min-width: 0; }
.user-name { display: block; font-weight: 500; overflow: hidden; text-overflow: ellipsis; font-size: 0.875rem; }
.user-role { display: block; font-size: 0.6875rem; color: var(--muted); }
.icon-btn { min-height: 32px; width: 32px; padding: 0; background: transparent; border-color: transparent; color: var(--text-2); border-radius: var(--radius-sm); }
.icon-btn:hover:not(:disabled) { background: var(--surface-3); color: var(--text); border-color: transparent; }

.main-col { min-width: 0; display: flex; flex-direction: column; }
.topbar {
  position: sticky; top: 0; z-index: 20;
  height: 56px; background: rgb(14 16 21 / 0.85); backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--line);
}
.topbar-inner {
  display: flex; align-items: center; justify-content: space-between; gap: 1rem;
  height: 100%; width: 100%; max-width: 1680px; margin: 0 auto;
  padding: 0 2rem;
}
.topbar-left { display: flex; align-items: center; gap: 0.75rem; }
.live-dot { display: inline-flex; align-items: center; gap: 0.5rem; margin-left: auto; font-size: 0.6875rem; color: var(--muted); letter-spacing: 0.04em; }
.live-dot > span { width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
.live-dot.on { color: var(--text-2); }
.live-dot.on > span { background: var(--ok); box-shadow: 0 0 0 0 color-mix(in srgb, var(--ok) 60%, transparent); animation: live-pulse 2.4s ease-out infinite; }
@keyframes live-pulse { 70% { box-shadow: 0 0 0 6px transparent; } 100% { box-shadow: 0 0 0 0 transparent; } }
.crumbs { display: flex; align-items: center; gap: 0.5rem; }
.crumb-pill {
  display: inline-flex; align-items: center; gap: 0.5rem;
  color: var(--text); font-weight: 600; font-size: 1rem;
}
.crumb-pill svg { color: var(--text-2); }
.crumb-title { letter-spacing: -0.01em; }
.search {
  display: flex; flex-direction: row; align-items: center; gap: 0.5rem; width: min(340px, 40vw);
  padding: 0 0.75rem; border: 1px solid var(--line-strong); border-radius: var(--radius-pill); background: var(--surface); color: var(--muted);
  transition: all 0.15s ease;
}
.search:focus-within { border-color: var(--text-2); background: var(--surface-2); box-shadow: 0 0 0 3px rgba(255, 255, 255, 0.05); }
.search input { flex: 1; min-width: 0; border: none; background: none; padding: 0; min-height: 34px; color: var(--text); font-size: 0.875rem; }
.search input:focus-visible { outline: none; }
kbd { font: 0.6875rem var(--mono); color: var(--text-2); border: 1px solid var(--line-strong); border-radius: var(--radius-pill); padding: 0.125rem 0.5rem; white-space: nowrap; background: var(--surface-2); }
main { padding: 2rem; width: 100%; max-width: 1680px; margin: 0 auto; }
.menu-btn, .scrim { display: none; }

.auth { max-width: 440px; margin: 0 auto; padding: 4rem 1rem; }
.auth-brand { display: flex; flex-direction: column; align-items: center; gap: 0.5rem; font-weight: 600; font-size: 1.25rem; margin-bottom: 1.5rem; }

@media (max-width: 900px) {
  .shell { grid-template-columns: minmax(0, 1fr); }
  .sidebar { position: fixed; z-index: 40; left: 0; width: 264px; transform: translateX(-100%); transition: transform 0.3s var(--ease); }
  .nav-open .sidebar { transform: none; box-shadow: 16px 0 48px -12px rgb(0 0 0 / 0.6); }
  .nav-open .scrim { display: block; position: fixed; inset: 0; z-index: 30; background: rgb(5 6 8 / 0.6); }
  .menu-btn { display: inline-flex; }
  .topbar-inner { padding: 0 1rem; gap: 0.5rem; }
  .crumbs > span, .crumbs > svg, kbd { display: none; }
  main { padding: 1.25rem 1rem; }
}
@media (max-width: 560px) {
  .search { width: auto; flex: 1; }
  .crumbs { display: none; }
}
</style>
