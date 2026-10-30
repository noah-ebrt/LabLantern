<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api.js'
import { passkeysSupported, usePasskey } from '../webauthn.js'
import { refreshSession } from '../session.js'

const router = useRouter()
const form = reactive({ username: '', password: '', totp_code: '' })
const error = ref('')
const busy = ref(false)

const canPasskey = passkeysSupported()

async function passkeyLogin() {
  if (!form.username || !form.password) {
    error.value = 'Enter username and password first, then confirm with your passkey.'
    return
  }
  busy.value = true
  error.value = ''
  try {
    const { token, options } = await api.post('/api/login/passkey/options', { username: form.username, password: form.password })
    const credential = await usePasskey(options)
    await api.post('/api/login/passkey', { token, credential })
    form.password = ''
    await refreshSession()
    router.push('/')
  } catch (e) {
    error.value = e.status === 429 ? 'Too many failed attempts. Please try again later.' : e.message
  } finally {
    busy.value = false
  }
}

async function submit() {
  busy.value = true
  error.value = ''
  try {
    await api.post('/api/login', form)
    form.password = ''
    form.totp_code = ''
    await refreshSession()
    router.push('/')
  } catch (e) {
    error.value = e.status === 429 ? 'Too many failed attempts. Please try again later.' : e.message
    form.totp_code = ''
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="card">
    <h1>vulnwatch</h1>
    <form @submit.prevent="submit">
      <label>Username<input v-model="form.username" name="username" autocomplete="username" required autofocus /></label>
      <label>Password<input v-model="form.password" name="password" type="password" autocomplete="current-password" required /></label>
      <label>Code from the authenticator app
        <input v-model="form.totp_code" name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required class="code" />
      </label>
      <button type="submit" class="primary" :disabled="busy">Sign in</button>
      <button v-if="canPasskey" type="button" :disabled="busy" @click="passkeyLogin">Sign in with passkey instead of a code</button>
      <p v-if="error" class="message error" role="alert">{{ error }}</p>
    </form>
  </section>
</template>
