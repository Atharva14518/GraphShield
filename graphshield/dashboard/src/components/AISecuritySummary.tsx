import { ScanReport } from '../types'
import { buildSecuritySummary } from '../ai'
import { Card, RiskBadge } from './UI'

interface AISecuritySummaryProps {
  report: ScanReport
}

export default function AISecuritySummary({ report }: AISecuritySummaryProps) {
  const summary = buildSecuritySummary(report)

  return (
    <Card
      title="AI Security Summary"
      badge={<RiskBadge level={report.risk_summary} size="sm" />}
      glowColor="var(--cyan)"
      style={{ marginBottom: 12 }}
    >
      <div style={{ display: 'grid', gap: 18 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 10 }}>
            <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '2rem', fontWeight: 400 }}>
              {summary.title}
            </h3>
            <span
              style={{
                borderRadius: 999,
                border: '1px solid rgba(16,185,129,0.3)',
                background: 'rgba(16,185,129,0.08)',
                color: 'var(--green)',
                padding: '4px 10px',
                fontSize: '.72rem',
                fontFamily: 'var(--font-mono)',
                letterSpacing: '.08em',
                textTransform: 'uppercase',
              }}
            >
              {summary.tone}
            </span>
          </div>
          <p style={{ color: 'var(--text-secondary)', lineHeight: 1.75, maxWidth: 980 }}>
            {summary.body}
          </p>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
            gap: 10,
          }}
        >
          {summary.stats.map((stat) => (
            <div
              key={stat.label}
              style={{
                borderRadius: 'var(--radius)',
                border: '1px solid var(--border-subtle)',
                background: 'linear-gradient(180deg, rgba(16,185,129,0.08), rgba(255,255,255,0.01))',
                padding: '14px 16px',
              }}
            >
              <div style={{ fontSize: '.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.08em' }}>
                {stat.label}
              </div>
              <div style={{ marginTop: 6, fontFamily: 'var(--font-display)', fontSize: '1.6rem' }}>
                {stat.value}
              </div>
            </div>
          ))}
        </div>
      </div>
    </Card>
  )
}
