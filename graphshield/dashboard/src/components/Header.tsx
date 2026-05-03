import { useEffect, useState } from 'react'
import { ScanReport } from '../types'
import { RiskBadge } from './UI'
import { formatTime } from '../utils'

interface HeaderProps { report: ScanReport; onReset: () => void }

export default function Header({ report, onReset }: HeaderProps) {
  const [scrolled, setScrolled] = useState(false)
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 16)
    window.addEventListener('scroll', onScroll)
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <header style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '10px 24px',
      background: scrolled ? 'rgba(0,0,0,0.8)' : 'transparent',
      backdropFilter: 'blur(16px)',
      borderBottom: '1px solid var(--border)',
      position: 'fixed', top: 0, zIndex: 100, width: '100%',
    }}>
      {/* Brand */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 28, height: 28, borderRadius: 10, background: '#111',
            display: 'grid', placeItems: 'center', color: '#fff', transition: 'transform .4s',
          }}
          onMouseEnter={e => { e.currentTarget.style.transform = 'rotate(360deg)' }}
          onMouseLeave={e => { e.currentTarget.style.transform = 'rotate(0deg)' }}
          >⌘</div>
          <div style={{
            fontFamily: 'var(--font-display)',
            fontSize: '20px',
            fontStyle: 'italic',
            color: '#EBEBEB',
          }}>
            GraphShield
          </div>
        </div>
        <div style={{ display: 'flex', gap: 20, marginLeft: 20 }}>
          {['Dashboard', 'Scan', 'Watch', 'Diff'].map((item) => (
            <span key={item} style={{ position: 'relative', fontFamily: 'var(--font-label)', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '.2em', color: 'rgba(235,235,235,.8)' }}>
              {item}
            </span>
          ))}
        </div>
        <div style={{ width: 1, height: 18, background: 'var(--border)' }} />
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '.72rem', color: 'var(--text-muted)' }}>
          <span style={{ color: 'var(--text-secondary)' }}>{report.target}</span>
          <span style={{ margin: '0 6px', color: 'var(--border)' }}>·</span>{formatTime(report.timestamp)}
        </div>
      </div>

      {/* Right */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <RiskBadge level={report.risk_summary} />
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: '.7rem',
          color: 'var(--text-muted)', padding: '2px 10px',
          background: 'var(--bg-elevated)', borderRadius: 4,
          border: '1px solid var(--border)',
        }}>
          {report.total_packages} pkgs · {report.scan_duration_seconds}s
        </div>
        <button
          onClick={onReset}
          style={{
            background: 'transparent', border: '1px solid var(--border)',
            color: '#10b981', borderRadius: '999px',
            borderColor: '#10b981',
            padding: '6px 18px', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: '.72rem',
            transition: 'all .25s', letterSpacing: '.05em',
            animation: 'pulse-glow 2s infinite',
          }}
          onMouseEnter={e => { e.currentTarget.style.boxShadow = '0 0 12px rgba(16,185,129,0.5)' }}
          onMouseLeave={e => { e.currentTarget.style.boxShadow = 'none' }}
        >
          NEW SCAN
        </button>
      </div>
    </header>
  )
}
