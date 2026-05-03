import { RiskLevel } from './types'

export const RISK_CONFIG: Record<RiskLevel, { color: string; glow: string; label: string; icon: string }> = {
  CLEAN:    { color: 'var(--green)',  glow: 'var(--green-dim)',  label: 'CLEAN',    icon: '✓' },
  LOW:      { color: 'var(--cyan)',   glow: 'var(--cyan-dim)',   label: 'LOW',       icon: '◉' },
  MEDIUM:   { color: 'var(--yellow)', glow: 'var(--yellow-dim)', label: 'MEDIUM',    icon: '◉' },
  HIGH:     { color: 'var(--orange)', glow: 'var(--orange-dim)', label: 'HIGH',      icon: '◉' },
  CRITICAL: { color: 'var(--red)',    glow: 'var(--red-dim)',    label: 'CRITICAL',  icon: '⚠' },
}

export function cvssToRisk(score: number): RiskLevel {
  if (score >= 9) return 'CRITICAL'
  if (score >= 7) return 'HIGH'
  if (score >= 4) return 'MEDIUM'
  if (score > 0)  return 'LOW'
  return 'CLEAN'
}

export function sensitivityToRisk(s: string): RiskLevel {
  const map: Record<string, RiskLevel> = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW' }
  return map[s] ?? 'CLEAN'
}

export function formatTime(iso: string) {
  return new Date(iso).toLocaleString('en-US', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

export function clsn(...args: (string | undefined | null | false)[]) {
  return args.filter(Boolean).join(' ')
}
