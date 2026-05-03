import { BlastRadiusResult } from '../types'
import { Card } from './UI'

interface AttackPathViewerProps { results: BlastRadiusResult[] }

export default function AttackPathViewer({ results }: AttackPathViewerProps) {
  const paths = results.flatMap(r =>
    r.attack_paths.map(ap => ({ ...ap, source: r.source_node, cvss: r.cvss_score }))
  ).sort((a, b) => b.exploit_score - a.exploit_score).slice(0, 8)

  return (
    <Card title={<span style={{ fontFamily: 'var(--font-display)', fontStyle: 'italic', fontSize: 20, fontWeight: 400 }}>Attack Paths</span>} badge={`${paths.length} paths`} glowColor="var(--cyan)">
      {paths.length === 0 ? (
        <div style={{ color: 'var(--green)', fontFamily: 'var(--font-mono)', fontSize: '.8rem', textAlign: 'center', padding: '20px 0' }}>
          ✓ No attack paths detected
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {paths.map((ap, idx) => (
            <div key={idx} style={{
              background: 'rgba(255,255,255,0.02)',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: '24px',
              padding: '10px 12px',
              transition: 'border-color .15s',
            }}
              onMouseEnter={e => (e.currentTarget.style.borderColor = 'rgba(255,45,85,.3)')}
              onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border-subtle)')}
            >
              {/* Path nodes */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap', marginBottom: 6 }}>
                {ap.path.map((node, i) => {
                  const isFirst = i === 0
                  const isLast = i === ap.path.length - 1
                  return (
                    <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      <span style={{
                        fontFamily: 'var(--font-label)',
                        fontSize: '11px',
                        letterSpacing: '.1em',
                        padding: '4px 12px',
                        borderRadius: 999,
                        background: isLast ? 'rgba(16,185,129,0.1)' : 'rgba(255,255,255,0.06)',
                        color: isLast ? '#10b981' : 'rgba(235,235,235,0.8)',
                        border: `1px solid ${isLast ? 'rgba(16,185,129,0.3)' : 'rgba(255,255,255,0.12)'}`,
                      }}>
                        {node}
                      </span>
                      {i < ap.path.length - 1 && (
                        <span style={{ color: '#10b981', fontSize: '.75rem' }}>→</span>
                      )}
                    </span>
                  )
                })}
              </div>

              {/* Meta */}
              <div style={{ display: 'flex', gap: 12, fontSize: '.68rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                <span style={{ color: 'var(--purple)' }}>{ap.sink_type}</span>
                <span>score <span style={{ color: 'var(--orange)' }}>{ap.exploit_score.toFixed(2)}</span></span>
                <span style={{ color: ap.exploitability === 'NETWORK' ? 'var(--red)' : 'var(--text-muted)' }}>
                  {ap.exploitability}
                </span>
                <span style={{ marginLeft: 'auto', color: 'var(--text-ghost)' }}>{ap.path_length} hop{ap.path_length !== 1 ? 's' : ''}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
