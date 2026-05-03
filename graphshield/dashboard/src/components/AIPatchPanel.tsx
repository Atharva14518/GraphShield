import { useMemo, useState } from 'react'
import { PatchRecommendation } from '../types'
import { Card, CvssPill } from './UI'

interface AIPatchPanelProps {
  patch_recommendations: PatchRecommendation[]
}

function normalizeConfidence(value: unknown): number {
  if (typeof value === 'number') {
    return Math.max(0, Math.min(1, value))
  }
  if (typeof value === 'string') {
    const trimmed = value.trim()
    const parsed = Number(trimmed)
    if (!Number.isNaN(parsed)) {
      return Math.max(0, Math.min(1, parsed))
    }
    const upper = trimmed.toUpperCase()
    if (upper === 'HIGH') return 0.9
    if (upper === 'MEDIUM') return 0.6
    if (upper === 'LOW') return 0.3
  }
  return 0
}

function normalizeBreakingChanges(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map(String).map((v) => v.trim()).filter(Boolean)
  }
  if (typeof value === 'string' && value.trim()) {
    return value
      .split(/[;,]/)
      .map((v) => v.trim())
      .filter(Boolean)
      .slice(0, 6)
  }
  return []
}

export default function AIPatchPanel({ patch_recommendations }: AIPatchPanelProps) {
  const [copied, setCopied] = useState<string | null>(null)

  const recommendations = useMemo(() => patch_recommendations.slice(0, 10), [patch_recommendations])
  const hasActionable = recommendations.some((rec) => normalizeConfidence((rec as unknown as { confidence?: unknown }).confidence) > 0)

  const copyCommand = async (command: string, pkg: string) => {
    try {
      await navigator.clipboard.writeText(command)
      setCopied(pkg)
      setTimeout(() => setCopied(null), 1200)
    } catch {
      setCopied(null)
    }
  }

  return (
    <Card
      title={
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 8, height: 8, borderRadius: 999, background: '#10b981', animation: 'pulse 1.5s infinite' }} />
          AI PATCH INTELLIGENCE
        </span>
      }
      badge={`${recommendations.length} packages`}
      glowColor="var(--green)"
      style={{ marginBottom: 12 }}
    >
      {!recommendations.length || !hasActionable ? (
        <div style={{ color: 'var(--text-muted)', fontSize: '.88rem' }}>
          Run scan with GROQ_API_KEY set to enable live Groq analysis
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {recommendations.map((rec, index) => {
            const confidence = normalizeConfidence((rec as unknown as { confidence?: unknown }).confidence)
            const confidencePct = Math.round(confidence * 100)
            const chips = normalizeBreakingChanges((rec as unknown as { breaking_changes?: unknown }).breaking_changes)

            return (
              <div
                key={`${rec.package_name}-${rec.current_version}`}
                style={{
                  background: 'var(--bg-elevated)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius)',
                  padding: '12px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 8 }}>
                  <div
                    style={{
                      width: 28,
                      height: 28,
                      borderRadius: 999,
                      display: 'grid',
                      placeItems: 'center',
                      background: 'rgba(16,185,129,0.12)',
                      color: 'var(--green)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '.74rem',
                    }}
                  >
                    {index + 1}
                  </div>
                  <strong style={{ fontSize: '.95rem' }}>{rec.package_name}</strong>
                  <CvssPill score={rec.cvss_score} />
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '.75rem' }}>
                    blast {rec.blast_radius_score.toFixed(1)}
                  </span>
                  <span style={{ color: confidencePct >= 80 ? 'var(--green)' : confidencePct >= 50 ? 'var(--yellow)' : 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '.75rem' }}>
                    {rec.confidence} confidence
                  </span>
                  <div style={{ marginLeft: 'auto', minWidth: 160 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '.65rem', color: 'var(--text-muted)', marginBottom: 4 }}>
                      <span>confidence</span>
                      <span>{confidencePct}%</span>
                    </div>
                    <div style={{ height: 5, borderRadius: 999, background: 'rgba(255,255,255,0.08)', overflow: 'hidden' }}>
                      <div
                        style={{
                          width: `${confidencePct}%`,
                          height: '100%',
                          background: 'linear-gradient(90deg, rgba(16,185,129,0.4), #10b981)',
                          transition: 'width .4s ease',
                        }}
                      />
                    </div>
                  </div>
                </div>

                <div style={{ fontSize: '.86rem', lineHeight: 1.55, color: 'var(--text-secondary)', marginBottom: 8 }}>
                  {rec.threat_explanation}
                </div>

                <div style={{ display: 'grid', gap: 6, marginBottom: 10 }}>
                  <div style={{ fontSize: '.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.08em' }}>
                    Upgrade command
                  </div>
                  <div
                    style={{
                      background: 'rgba(16,185,129,0.08)',
                      border: '1px solid rgba(16,185,129,0.25)',
                      borderRadius: 8,
                      padding: '8px 10px',
                      display: 'flex',
                      gap: 8,
                      alignItems: 'center',
                    }}
                  >
                    <code style={{ color: '#10b981', fontFamily: 'var(--font-mono)', fontSize: '.75rem', flex: 1 }}>{rec.upgrade_command}</code>
                    <button
                      onClick={() => copyCommand(rec.upgrade_command, rec.package_name)}
                      style={{
                        border: '1px solid rgba(16,185,129,0.4)',
                        background: 'transparent',
                        color: '#10b981',
                        borderRadius: 999,
                        padding: '3px 10px',
                        cursor: 'pointer',
                        fontSize: '.68rem',
                      }}
                    >
                      {copied === rec.package_name ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                </div>

                <div style={{ fontSize: '.76rem', color: 'var(--text-muted)', marginBottom: 10, lineHeight: 1.6 }}>
                  {rec.attack_path_summary}
                </div>

                {chips.length > 0 && (
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10, alignItems: 'center' }}>
                    <span style={{ fontSize: '.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.08em' }}>
                      Breaking
                    </span>
                    {chips.map((chip) => (
                      <span
                        key={chip}
                        style={{
                          fontSize: '.66rem',
                          color: '#ef4444',
                          background: 'rgba(239,68,68,0.1)',
                          border: '1px solid rgba(239,68,68,0.3)',
                          borderRadius: 999,
                          padding: '2px 8px',
                          fontFamily: 'var(--font-label)',
                          letterSpacing: '.04em',
                        }}
                      >
                        {chip}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </Card>
  )
}
