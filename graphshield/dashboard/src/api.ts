/** API client for the GraphShield FastAPI backend */

export interface ScanRequest {
  target: string
  use_agent?: boolean
  groq_api_key?: string
}

export interface StatusResponse {
  db_ready: boolean
  db_entries: number
  bloom_ready: boolean
  bloom_items: number
  bloom_fp_rate: number
  groq_configured: boolean
}

const BASE = ''  // Vite proxy forwards /api → http://127.0.0.1:8000
const SCAN_TIMEOUT_MS = 30_000

export async function fetchStatus(): Promise<StatusResponse> {
  const res = await fetch(`${BASE}/api/status`)
  if (!res.ok) throw new Error(`Status check failed: ${res.statusText}`)
  return res.json()
}

export async function runScan(req: ScanRequest): Promise<Record<string, unknown>> {
  const res = await fetch(`${BASE}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    signal: AbortSignal.timeout(SCAN_TIMEOUT_MS),
    body: JSON.stringify(req),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || res.statusText)
  }
  return res.json()
}

export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${BASE}/health`, { signal: AbortSignal.timeout(2000) })
    return res.ok
  } catch {
    return false
  }
}
