import { useMemo, useState } from 'react'
import { buildPrDescription } from '../ai'
import { ScanReport } from '../types'
import { Card } from './UI'

interface PRDescriptionGeneratorProps {
  report: ScanReport
}

export default function PRDescriptionGenerator({ report }: PRDescriptionGeneratorProps) {
  const [copied, setCopied] = useState(false)
  const description = useMemo(() => buildPrDescription(report), [report])

  const copyText = async () => {
    try {
      await navigator.clipboard.writeText(description)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1200)
    } catch {
      setCopied(false)
    }
  }

  return (
    <Card
      title="Generate GitHub PR description"
      badge="Groq-powered"
      glowColor="var(--green)"
    >
      <div style={{ display: 'grid', gap: 12 }}>
        <pre
          style={{
            margin: 0,
            whiteSpace: 'pre-wrap',
            fontFamily: 'var(--font-mono)',
            fontSize: '.76rem',
            color: 'var(--text-secondary)',
            background: 'var(--bg-elevated)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius)',
            padding: '14px',
            lineHeight: 1.7,
          }}
        >
          {description}
        </pre>
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button
            onClick={copyText}
            style={{
              borderRadius: 999,
              border: '1px solid rgba(16,185,129,0.4)',
              background: 'rgba(16,185,129,0.08)',
              color: 'var(--green)',
              padding: '8px 14px',
              cursor: 'pointer',
              fontFamily: 'var(--font-mono)',
              fontSize: '.72rem',
            }}
          >
            {copied ? 'Copied PR description' : 'Copy PR description'}
          </button>
        </div>
      </div>
    </Card>
  )
}
