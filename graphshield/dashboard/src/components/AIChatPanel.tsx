import { useMemo, useState } from 'react'
import { buildChatPrompts } from '../ai'
import { ScanReport } from '../types'

interface AIChatPanelProps {
  report: ScanReport
}

export default function AIChatPanel({ report }: AIChatPanelProps) {
  const prompts = useMemo(() => buildChatPrompts(report), [report])
  const [active, setActive] = useState(0)

  return (
    <aside className="ai-chat-panel">
      <div
        style={{
          borderRadius: '18px 18px 0 0',
          borderBottom: '1px solid var(--border-subtle)',
          padding: '12px 14px',
          background: 'linear-gradient(180deg, rgba(16,185,129,0.18), rgba(255,255,255,0.02))',
        }}
      >
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '.72rem', letterSpacing: '.09em', textTransform: 'uppercase', color: 'var(--green)' }}>
          GraphShield AI
        </div>
        <div style={{ marginTop: 4, color: 'var(--text-muted)', fontSize: '.78rem' }}>
          Context: this scan
        </div>
      </div>

      <div style={{ padding: 14, display: 'grid', gap: 12 }}>
        <div
          style={{
            borderRadius: 'var(--radius)',
            border: '1px solid rgba(16,185,129,0.15)',
            background: 'rgba(255,255,255,0.02)',
            padding: '12px 14px',
            color: 'var(--text-secondary)',
            fontSize: '.84rem',
            lineHeight: 1.7,
          }}
        >
          {prompts[active]?.answer}
        </div>

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {prompts.map((prompt, index) => (
            <button
              key={prompt.question}
              onClick={() => setActive(index)}
              style={{
                borderRadius: 999,
                border: index === active ? '1px solid rgba(16,185,129,0.45)' : '1px solid var(--border-subtle)',
                background: index === active ? 'rgba(16,185,129,0.12)' : 'var(--bg-surface)',
                color: index === active ? 'var(--green)' : 'var(--text-secondary)',
                padding: '8px 10px',
                cursor: 'pointer',
                fontSize: '.72rem',
                fontFamily: 'var(--font-mono)',
              }}
            >
              {prompt.question}
            </button>
          ))}
        </div>
      </div>
    </aside>
  )
}
