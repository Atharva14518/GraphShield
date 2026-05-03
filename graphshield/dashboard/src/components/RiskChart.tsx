import { useEffect, useRef } from 'react'
import { ScanReport } from '../types'
import { Card } from './UI'

interface RiskChartProps { report: ScanReport }

export default function RiskChart({ report: r }: RiskChartProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const dpr = window.devicePixelRatio || 1
    canvas.width = 220 * dpr
    canvas.height = 220 * dpr
    ctx.scale(dpr, dpr)

    const W = 220, H = 220
    const cx = W / 2, cy = H / 2

    const segments = [
      { label: 'Critical', value: r.critical_count,  color: '#ff2d55' },
      { label: 'High',     value: r.high_count,      color: '#ff8c00' },
      { label: 'Medium',   value: r.medium_count||0, color: '#ffd700' },
      { label: 'Clean',    value: Math.max(0, r.total_packages - r.vulnerable_packages), color: '#00ff88' },
    ].filter(s => s.value > 0)

    const total = segments.reduce((s, d) => s + d.value, 0) || 1

    ctx.clearRect(0, 0, W, H)

    // ── Draw arc segments ──
    let angle = -Math.PI / 2
    const outerR = 85, innerR = 55, gap = 0.025

    segments.forEach(seg => {
      const sweep = (seg.value / total) * Math.PI * 2 - gap
      ctx.beginPath()
      ctx.arc(cx, cy, outerR, angle, angle + sweep)
      ctx.arc(cx, cy, innerR, angle + sweep, angle, true)
      ctx.closePath()
      ctx.fillStyle = seg.color
      ctx.shadowColor = seg.color
      ctx.shadowBlur = 12
      ctx.fill()
      ctx.shadowBlur = 0
      angle += sweep + gap
    })

    // ── Inner fill ──
    ctx.beginPath()
    ctx.arc(cx, cy, innerR - 1, 0, Math.PI * 2)
    ctx.fillStyle = '#060d14'
    ctx.fill()

    // ── Centre text ──
    ctx.textAlign = 'center'
    ctx.fillStyle = r.vulnerable_packages > 0 ? '#ff2d55' : '#00ff88'
    ctx.font = `bold 32px 'Orbitron', monospace`
    ctx.fillText(String(r.vulnerable_packages), cx, cy + 5)
    ctx.fillStyle = '#3d6080'
    ctx.font = `10px 'JetBrains Mono', monospace`
    ctx.fillText('VULNERABLE', cx, cy + 20)

    // ── Legend ──
    const legendY = H - 36
    const legendItems = segments.slice(0, 4)
    const itemWidth = W / legendItems.length
    legendItems.forEach((seg, i) => {
      const lx = i * itemWidth + itemWidth / 2
      ctx.fillStyle = seg.color
      ctx.fillRect(lx - 10, legendY, 10, 3)
      ctx.fillStyle = '#3d6080'
      ctx.font = `9px 'JetBrains Mono', monospace`
      ctx.fillText(`${seg.label} ${seg.value}`, lx + 2, legendY + 10)
    })

    // ── Radar lines on outer ring ──
    ctx.strokeStyle = 'rgba(0,212,255,.08)'
    ctx.lineWidth = 1
    for (let i = 0; i < 12; i++) {
      const a = (i / 12) * Math.PI * 2
      ctx.beginPath()
      ctx.moveTo(cx + Math.cos(a) * (innerR - 2), cy + Math.sin(a) * (innerR - 2))
      ctx.lineTo(cx + Math.cos(a) * (outerR + 2), cy + Math.sin(a) * (outerR + 2))
      ctx.stroke()
    }
  }, [r])

  return (
    <Card title="◎ Risk Breakdown" glowColor="var(--cyan)">
      <div style={{ display: 'flex', justifyContent: 'center', padding: '8px 0' }}>
        <canvas
          ref={canvasRef}
          style={{ width: 220, height: 220 }}
        />
      </div>
    </Card>
  )
}
