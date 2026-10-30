<script setup>
import { computed, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api.js'
import { refreshSession } from '../session.js'

const router = useRouter()
const step = ref(1)
const token = ref('')
const totp = ref(null)
const form = reactive({ username: 'admin', password: '', totp_code: '' })
const error = ref('')
const busy = ref(false)

const qrSrc = computed(() =>
  totp.value ? `data:image/svg+xml;charset=utf-8,${encodeURIComponent(totp.value.qr_svg)}` : '',
)

async function checkToken() {
  busy.value = true
  error.value = ''
  try {
    totp.value = await api.post('/api/setup/totp', { setup_token: token.value.trim() })
    step.value = 2
  } catch (e) {
    error.value = e.status === 429 ? 'Too many failed attempts. Please try again later.' : e.message
  } finally {
    busy.value = false
  }
}

async function complete() {
  busy.value = true
  error.value = ''
  try {
    await api.post('/api/setup/complete', { setup_token: token.value.trim(), ...form })
    await refreshSession()
    router.push('/login')
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="card">
    <h1>Setup</h1>

    <form v-if="step === 1" @submit.prevent="checkToken">
      <p>The setup token is in the server log:</p>
      <pre class="cmd">docker compose logs server | grep "Setup token"</pre>
      <label>Setup token<input v-model="token" name="setup_token" autocomplete="off" spellcheck="false" required autofocus /></label>
      <button type="submit" class="primary" :disabled="busy">Continue</button>
      <p v-if="error" class="message error" role="alert">{{ error }}</p>
    </form>

    <form v-else @submit.prevent="complete">
      <h2>Second factor</h2>
      <p>Scan the code with an authenticator app (or enter the key manually).</p>
      <img :src="qrSrc" alt="QR code for the authenticator app" class="qr" width="200" height="200" />
      <p class="mono secret-line">{{ totp.totp_secret }}</p>
      <h2>Administrator</h2>
      <label>Username<input v-model="form.username" name="username" autocomplete="username" required /></label>
      <label>Password (at least 12 characters)<input v-model="form.password" name="password" type="password" minlength="12" autocomplete="new-password" required /></label>
      <label>Current code from the app
        <input v-model="form.totp_code" name="totp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required class="code" />
      </label>
      <button type="submit" class="primary" :disabled="busy">Finish setup</button>
      <p v-if="error" class="message error" role="alert">{{ error }}</p>
    </form>
  </section>
</template>
