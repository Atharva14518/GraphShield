import { GLOSSARY } from '../ai'
import { Card } from './UI'

export default function AIExplainerPanel() {
  return (
    <Card title="What does this mean?" badge="Hover any term" glowColor="var(--orange)">
      <div style={{ display: 'grid', gap: 10 }}>
        {GLOSSARY.map((item) => (
          <div
            key={item.term}
            title={item.detail}
            style={{
              borderRadius: 'var(--radius)',
              border: '1px solid var(--border-subtle)',
              background: 'var(--bg-elevated)',
              padding: '12px 14px',
            }}
          >
            <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', fontSize: '.8rem', marginBottom: 6 }}>
              {item.term}
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: '.82rem', lineHeight: 1.6 }}>
              {item.detail}
            </div>
          </div>
        ))}
      </div>
    </Card>
  )
}
