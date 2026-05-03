import { CircularTrustCluster } from '../types'
import { Card, RiskBadge, CvssPill } from './UI'

interface SCCPanelProps { clusters: CircularTrustCluster[] }

export default function SCCPanel({ clusters }: SCCPanelProps) {
  return (
    <Card
      title="⟳ Circular Trust Clusters (Tarjan SCC)"
      badge={`${clusters.length} detected`}
      glowColor={clusters.length > 0 ? 'var(--purple)' : undefined}
    >
      {clusters.length === 0 ? (
        <div style={{ color: 'var(--green)', fontFamily: 'var(--font-mono)', fontSize: '.8rem', textAlign: 'center', padding: '20px 0' }}>
          ✓ No circular trust chains detected
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {clusters.map((c, i) => (
            <div key={i} style={{
              background: 'var(--bg-elevated)',
              border: `1px solid ${c.risk_level === 'CRITICAL' ? 'rgba(255,45,85,.2)' : c.risk_level === 'HIGH' ? 'rgba(255,140,0,.15)' : 'var(--border-subtle)'}`,
              borderRadius: 'var(--radius)',
              padding: '12px 14px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
                <RiskBadge level={c.risk_level} size="sm" />
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '.72rem', color: 'var(--text-secondary)' }}>
                  {c.size} packages in cycle
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '.7rem', color: 'var(--text-muted)' }}>
                  blast radius {c.combined_blast_radius}
                </span>
                {c.max_cvss_in_cluster > 0 && (
                  <span style={{ marginLeft: 'auto' }}>
                    <CvssPill score={c.max_cvss_in_cluster} />
                  </span>
                )}
              </div>

              {/* Cycle visualisation */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
                {c.nodes.map((node, ni) => (
                  <span key={ni} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={{
                      fontFamily: 'var(--font-mono)', fontSize: '.72rem', fontWeight: 600,
                      padding: '2px 8px', borderRadius: 3,
                      background: 'rgba(191,95,255,.08)',
                      color: 'var(--purple)',
                      border: '1px solid rgba(191,95,255,.2)',
                    }}>{node}</span>
                    <span style={{ color: 'var(--text-ghost)', fontSize: '.78rem' }}>
                      {ni === c.nodes.length - 1 ? '↺' : '→'}
                    </span>
                  </span>
                ))}
              </div>

              {/* Risk explanation */}
              <div style={{ marginTop: 8, fontSize: '.7rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                {c.risk_level === 'CRITICAL' && '⚠ Compromising any node in this cluster transitively compromises all others'}
                {c.risk_level === 'HIGH' && '⚡ High-risk circular dependency — mutual trust escalates blast radius'}
                {c.risk_level === 'MEDIUM' && 'ℹ Circular dependency detected — review trust boundaries'}
                {c.risk_level === 'LOW' && 'ℹ Benign circular reference — monitor for CVE introduction'}
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
