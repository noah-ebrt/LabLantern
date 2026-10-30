import { createRouter, createWebHistory } from 'vue-router'
import { routeFor } from './guard.js'
import { refreshSession, session } from './session.js'
import LoginView from './views/LoginView.vue'
import OverviewView from './views/OverviewView.vue'
import SettingsView from './views/SettingsView.vue'
import SetupView from './views/SetupView.vue'
import SystemsView from './views/SystemsView.vue'
import FindingsView from './views/FindingsView.vue'
import RunsView from './views/RunsView.vue'
import HistoryView from './views/HistoryView.vue'
import EarlyWarningsView from './views/EarlyWarningsView.vue'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: OverviewView },
    { path: '/systeme', component: SystemsView },
    { path: '/funde', component: FindingsView },
    { path: '/laeufe', component: RunsView },
    { path: '/verlauf', component: HistoryView },
    { path: '/fruehwarnungen', component: EarlyWarningsView },
    { path: '/einstellungen', component: SettingsView },
    { path: '/login', component: LoginView },
    { path: '/einrichtung', component: SetupView },
    { path: '/:rest(.*)*', redirect: '/' },
  ],
})

router.beforeEach(async (to) => {
  if (!session.loaded) await refreshSession()
  return routeFor(session, to.path) ?? true
})
