let csrf = null

export function setCsrf(token) {
  csrf = token
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

function messageFrom(status, body) {
  const d = body && body.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d)) {
    return d.map((e) => `${(e.loc || []).slice(1).join('.')}: ${e.msg}`).join('; ')
  }
  return `Request failed (${status})`
}

async function request(method, url, body, withTotal = false) {
  const headers = {}
  if (method !== 'GET') {
    headers['Content-Type'] = 'application/json'
    if (csrf) headers['X-CSRF-Token'] = csrf
  }
  const res = await fetch(url, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  let data = null
  try {
    data = await res.json()
  } catch {
    /* leere or nicht-JSON-Antwort */
  }
  if (!res.ok) throw new ApiError(res.status, messageFrom(res.status, data))
  return withTotal ? { items: data, total: Number(res.headers.get('X-Total-Count') ?? data?.length ?? 0) } : data
}

export const api = {
  get: (url) => request('GET', url),
  // Listen mit Gesamtzahl aus X-Total-Count (für Seitenumschaltung)
  page: (url) => request('GET', url, undefined, true),
  post: (url, body = {}) => request('POST', url, body),
  put: (url, body = {}) => request('PUT', url, body),
  del: (url) => request('DELETE', url),
}
