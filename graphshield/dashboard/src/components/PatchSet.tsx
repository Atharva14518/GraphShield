import { MinimumPatchSet, BlastRadiusResult } from '../types'
import { Card, CvssPill } from './UI'

interface PatchSetProps { mps: MinimumPatchSet; results: BlastRadiusResult[] }

export default function PatchSet({ mps, results }: PatchSetProps) {
  const byNode = Object.fromEntries(results.map(r => [r.source_node, r]))

  return (
    <Card
      title="⬡ Minimum Patch Set"
      badge={mps.savings_percent > 0 ? `↓ ${mps.savings_percent.toFixed(0)}% savings` : undefined}
      glowColor="var(--green)"
    >
      {/* Summary */}
      <div style={{
        background: 'rgba(0,255,136,.06)',
        border: '1px solid rgba(0,255,136,.15)',
        borderRadius: 'var(--radius-sm)',
        padding: '8px 12px',
        fontFamily: 'var(--font-mono)',
        fontSize: '.74rem',
        color: 'var(--text-secondary)',
        marginBottom: 12,
        lineHeight: 1.6,
      }}>
        {mps.reasoning}
      </div>

      {/* Effort badge */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
        {[
          { label: 'Effort', value: mps.estimated_effort, color: mps.estimated_effort === 'LOW' ? 'var(--green)' : mps.estimated_effort === 'MEDIUM' ? 'var(--yellow)' : 'var(--red)' },
          { label: 'Updates', value: `${mps.packages_to_update_count} / ${mps.total_vulnerable_count}`, color: 'var(--cyan)' },
          { label: 'Paths Eliminated', value: String(mps.attack_paths_eliminated), color: 'var(--purple)' },
        ].map(({ label, value, color }) => (
          <div key={label} style={{
            flex: 1, minWidth: 80,
            background: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-sm)', padding: '6px 10px', textAlign: 'center',
          }}>
            <div style={{ fontSize: '.62rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '.08em' }}>{label}</div>
            <div style={{ fontSize: '.88rem', fontWeight: 700, color, fontFamily: 'var(--font-mono)', marginTop: 2 }}>{value}</div>
          </div>
        ))}
      </div>

      {/* Update order */}
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '.68rem', color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '.08em' }}>
        Update order
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {mps.update_order.map((pkg, i) => {
          const vuln = byNode[pkg]
          return (
            <div key={pkg} style={{
              display: 'flex', alignItems: 'center', gap: 10,
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius)',
              padding: '8px 12px',
              transition: 'border-color .15s',
            }}
              onMouseEnter={e => (e.currentTarget.style.borderColor = 'rgba(0,255,136,.25)')}
              onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border-subtle)')}
            >
              <div style={{
                width: 22, height: 22, borderRadius: '50%',
                background: 'var(--green)', color: 'var(--bg-void)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: '.68rem', fontWeight: 800, flexShrink: 0,
              }}>{i + 1}</div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '.84rem', color: 'var(--text-primary)' }}>{pkg}</div>
                {vuln && <div style={{ fontSize: '.68rem', color: 'var(--text-muted)', marginTop: 1 }}>
                  blast {vuln.blast_radius_score.toFixed(1)} · {vuln.reachable_count} downstream
                </div>}
              </div>
              {vuln && <CvssPill score={vuln.cvss_score} />}
            </div>
          )
        })}
      </div>
    </Card>
  )
}
