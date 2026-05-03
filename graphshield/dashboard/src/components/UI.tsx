import React, { CSSProperties, useEffect, useRef, useState } from 'react'
import { RiskLevel } from '../types'
import { RISK_CONFIG } from '../utils'

/* ── Risk Badge ───────────────────────────────────────────────────── */
interface RiskBadgeProps { level: RiskLevel; size?: 'sm' | 'md' | 'lg' }
export function RiskBadge({ level, size = 'md' }: RiskBadgeProps) {
  const cfg = RISK_CONFIG[level]
  const padding = size === 'sm' ? '2px 8px' : size === 'lg' ? '6px 18px' : '3px 12px'
  const fontSize = size === 'sm' ? '.68rem' : size === 'lg' ? '.9rem' : '.75rem'
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding, borderRadius: 100,
      background: cfg.glow,
      border: `1px solid ${cfg.color}44`,
      color: cfg.color,
      fontFamily: 'var(--font-mono)',
      fontSize, fontWeight: 700,
      letterSpacing: '.1em',
      textTransform: 'uppercase',
    }}>
      <span style={{ fontSize: '.85em' }}>{cfg.icon}</span>
      {cfg.label}
    </span>
  )
}

/* ── CVSS Pill ────────────────────────────────────────────────────── */
interface CvssPillProps { score: number }
export function CvssPill({ score }: CvssPillProps) {
  const color = score >= 9 ? 'var(--red)' : score >= 7 ? 'var(--orange)' : score >= 4 ? 'var(--yellow)' : score > 0 ? 'var(--cyan)' : 'var(--text-muted)'
  const bg = score >= 9 ? 'var(--red-dim)' : score >= 7 ? 'var(--orange-dim)' : score >= 4 ? 'var(--yellow-dim)' : score > 0 ? 'var(--cyan-dim)' : 'transparent'
  return (
    <span style={{
      display: 'inline-block',
      padding: '1px 8px', borderRadius: 100,
      background: bg, color,
      fontFamily: 'var(--font-mono)',
      fontSize: '.75rem', fontWeight: 700,
      border: `1px solid ${color}33`,
    }}>
      {score.toFixed(1)}
    </span>
  )
}

/* ── Mono Chip ────────────────────────────────────────────────────── */
interface ChipProps { children: React.ReactNode; color?: string }
export function MonoChip({ children, color = 'var(--text-secondary)' }: ChipProps) {
  return (
    <span style={{
      fontFamily: 'var(--font-mono)',
      fontSize: '.72rem', fontWeight: 600,
      color, padding: '1px 6px',
      background: 'rgba(0,212,255,0.06)',
      border: '1px solid var(--border)',
      borderRadius: 3,
    }}>{children}</span>
  )
}

/* ── Section Card ─────────────────────────────────────────────────── */
interface CardProps {
  title: React.ReactNode
  badge?: React.ReactNode
  children: React.ReactNode
  style?: CSSProperties
  glowColor?: string
}
export function Card({ title, badge, children, style, glowColor }: CardProps) {
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius-lg)',
      overflow: 'hidden',
      boxShadow: glowColor
        ? `0 0 0 1px ${glowColor}22, inset 0 1px 0 ${glowColor}11`
        : '0 2px 16px rgba(0,0,0,.5)',
      ...style,
    }}>
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '10px 16px',
        borderBottom: '1px solid var(--border-subtle)',
        background: 'rgba(0,212,255,0.03)',
      }}>
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '.72rem', fontWeight: 700,
          color: 'var(--text-secondary)',
          textTransform: 'uppercase', letterSpacing: '.1em',
          display: 'flex', alignItems: 'center', gap: 6,
        }}>{title}</span>
        {badge && <span style={{ fontSize: '.72rem', color: 'var(--text-muted)' }}>{badge}</span>}
      </div>
      <div style={{ padding: 16 }}>{children}</div>
    </div>
  )
}

/* ── Stat Card ────────────────────────────────────────────────────── */
interface StatCardProps { label: string; value: string | number; sub?: string; color?: string; glow?: boolean }
export function StatCard({ label, value, sub, color = 'var(--text-primary)', glow }: StatCardProps) {
  const cardRef = useRef<HTMLDivElement>(null)
  const handleMouseMove: React.MouseEventHandler<HTMLDivElement> = (e) => {
    const rect = e.currentTarget.getBoundingClientRect()
    e.currentTarget.style.setProperty('--mouse-x', `${e.clientX - rect.left}px`)
    e.currentTarget.style.setProperty('--mouse-y', `${e.clientY - rect.top}px`)
  }

  return (
    <div
      ref={cardRef}
      className="spotlight-card reveal"
      onMouseMove={handleMouseMove}
      style={{
        transition: 'all 0.6s cubic-bezier(0.16, 1, 0.3, 1)',
        boxShadow: glow ? `0 0 20px ${color}22` : undefined,
      }}
    >
      <div style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '.2em', color: 'rgba(235,235,235,0.5)', fontWeight: 500, fontFamily: 'var(--font-label)' }}>{label}</div>
      <div style={{ fontSize: '48px', fontWeight: 200, color, lineHeight: 1.05, marginTop: 8, fontFamily: 'var(--font-display)' }}>
        {typeof value === 'number' ? <CountUp value={value} /> : value}
      </div>
      {sub && <div style={{ fontSize: '.72rem', color: 'var(--text-muted)', marginTop: 3 }}>{sub}</div>}
    </div>
  )
}

export function CountUp({ value }: { value: number }) {
  const [display, setDisplay] = useState(0)
  useEffect(() => {
    let frame = 0
    const steps = 28
    const start = 0
    const delta = value - start
    const tick = () => {
      frame += 1
      const progress = Math.min(1, frame / steps)
      setDisplay(Math.round(start + delta * progress))
      if (progress < 1) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  }, [value])
  return <>{display}</>
}

/* ── Divider ─────────────────────────────────────────────────────── */
export function CyberDivider() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, margin: '8px 0' }}>
      <div style={{ flex: 1, height: 1, background: 'linear-gradient(90deg, transparent, var(--border), transparent)' }} />
      <div style={{ width: 4, height: 4, background: 'var(--cyan)', borderRadius: '50%', boxShadow: '0 0 6px var(--cyan)' }} />
      <div style={{ flex: 1, height: 1, background: 'linear-gradient(90deg, transparent, var(--border), transparent)' }} />
    </div>
  )
}

/* ── Progress Bar ─────────────────────────────────────────────────── */
interface ProgressBarProps { value: number; max?: number; color?: string; label?: string }
export function ProgressBar({ value, max = 100, color = 'var(--cyan)', label }: ProgressBarProps) {
  const pct = Math.min(100, (value / max) * 100)
  return (
    <div>
      {label && <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '.72rem', color: 'var(--text-muted)', marginBottom: 4 }}>
        <span>{label}</span><span style={{ color: 'var(--text-secondary)' }}>{value}/{max}</span>
      </div>}
      <div style={{ height: 4, background: 'var(--bg-elevated)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{
          height: '100%', width: `${pct}%`,
          background: `linear-gradient(90deg, ${color}88, ${color})`,
          borderRadius: 2,
          boxShadow: `0 0 8px ${color}66`,
          transition: 'width 1s ease',
        }} />
      </div>
    </div>
  )
}

/* ── Terminal Text ────────────────────────────────────────────────── */
interface TerminalTextProps { children: React.ReactNode; color?: string }
export function TerminalText({ children, color = 'var(--green)' }: TerminalTextProps) {
  return (
    <span style={{ fontFamily: 'var(--font-mono)', color, fontSize: '.82rem' }}>
      <span style={{ color: 'var(--text-muted)' }}>$ </span>{children}
      <span style={{ animation: 'blink 1s step-end infinite', color }}>█</span>
    </span>
  )
}
