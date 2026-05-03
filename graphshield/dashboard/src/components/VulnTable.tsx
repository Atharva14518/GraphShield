import { BlastRadiusResult } from '../types'
import { Card, CountUp, CvssPill, RiskBadge, ProgressBar } from './UI'
import { sensitivityToRisk } from '../utils'

interface VulnTableProps { results: BlastRadiusResult[] }

export default function VulnTable({ results }: VulnTableProps) {
  const maxBlast = Math.max(...results.map(r => r.blast_radius_score), 1)

  return (
    <Card title="⚡ Vulnerabilities by Blast Radius" badge={`${results.length} packages`} glowColor="var(--red)">
      {results.length === 0 ? (
        <div style={{ color: 'var(--green)', fontFamily: 'var(--font-mono)', fontSize: '.82rem', textAlign: 'center', padding: '24px 0' }}>
          ✓ No vulnerabilities detected
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '2fr .9fr .9fr .8fr', gap: 8, padding: '0 8px 10px', borderBottom: '1px solid rgba(255,255,255,0.06)', fontFamily: 'var(--font-label)', fontSize: 10, letterSpacing: '.15em', textTransform: 'uppercase', color: 'rgba(235,235,235,0.4)' }}>
            <span>Package</span><span>CVE</span><span>CVSS</span><span>Risk</span>
          </div>
          {results.map((r) => (
            <div key={r.source_node} style={{
              background: 'transparent',
              borderBottom: '1px solid rgba(255,255,255,0.04)',
              borderRadius: 0,
              padding: '12px 8px',
              transition: 'border-color .15s',
              cursor: 'default',
            }}
              onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--border-bright)')}
              onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border-subtle)')}
            >
              {/* Top row */}
              <div style={{ display: 'grid', alignItems: 'center', gridTemplateColumns: '2fr .9fr .9fr .8fr', gap: 8, marginBottom: 8 }}>
                <span style={{ fontFamily: 'Inter', fontWeight: 400, color: '#EBEBEB', fontSize: '.92rem', flex: 1 }}>
                  {r.source_node}
                </span>
                <span style={{ fontFamily: 'var(--font-label)', fontSize: 11, color: 'rgba(235,235,235,0.6)' }}>{r.cve_id}</span>
                <span style={{ color: '#10b981', fontWeight: 500 }}><CountUp value={Math.round(r.cvss_score)} /></span>
                <span><RiskBadge level={sensitivityToRisk(r.data_sensitivity)} size="sm" /></span>
              </div>

              {/* CVE ID */}
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '.7rem', color: 'var(--text-muted)', marginBottom: 7, display: 'none' }}>
                <span style={{ color: 'var(--red)' }}>{r.cve_id}</span>
                {r.sink_types.length > 0 && (
                  <span style={{ marginLeft: 10, color: 'var(--purple)' }}>
                    {r.sink_types.join(', ')}
                  </span>
                )}
              </div>

              {/* Blast radius bar */}
              <ProgressBar
                value={Math.round(r.blast_radius_score)}
                max={Math.round(maxBlast)}
                color={r.cvss_score >= 9 ? 'var(--red)' : r.cvss_score >= 7 ? 'var(--orange)' : 'var(--yellow)'}
                label={`blast radius score · ${r.reachable_count} downstream`}
              />
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
