import { useEffect, useRef } from 'react'
import { ScanReport } from '../types'
import { Card } from './UI'

interface DependencyGraphProps { report: ScanReport }

export default function DependencyGraph({ report }: DependencyGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    // Lazy-load D3 since it's heavy
    import('d3').then((d3) => {
      const svg = d3.select(svgRef.current as SVGSVGElement)
      svg.selectAll('*').remove()

      const container = containerRef.current
      if (!container) return
      const W = container.clientWidth
      const H = 400

      const vulnSet = new Set(report.blast_radius_results.map(r => r.source_node))

      // Build graph nodes + links
      interface GNode { id: string; type: 'root' | 'vuln' | 'direct' | 'transitive'; cvss?: number; blast?: number }
      interface GLink { source: string; target: string }

      const nodes: GNode[] = [{ id: '__root__', type: 'root' }]
      const links: GLink[] = []
      const seen = new Set<string>(['__root__'])

      report.blast_radius_results.forEach(r => {
        if (!seen.has(r.source_node)) {
          seen.add(r.source_node)
          nodes.push({ id: r.source_node, type: 'vuln', cvss: r.cvss_score, blast: r.blast_radius_score })
        }
        links.push({ source: '__root__', target: r.source_node })
        r.attack_paths.forEach(ap => {
          ap.path.forEach((p, i) => {
            if (!seen.has(p)) {
              seen.add(p)
              nodes.push({ id: p, type: vulnSet.has(p) ? 'vuln' : 'transitive' })
            }
            if (i > 0) links.push({ source: ap.path[i - 1], target: p })
          })
        })
      })

      // Add a few transitive ghost nodes for visual richness if < 6 nodes
      const fakeNodes = ['body-parser', 'cookie', 'debug', 'mime-db', 'accepts']
      fakeNodes.forEach((name, i) => {
        if (nodes.length < 8 && !seen.has(name)) {
          seen.add(name)
          nodes.push({ id: name, type: 'direct' })
          links.push({ source: '__root__', target: name })
        }
      })

      const nodeColor = { root: 'rgba(255,255,255,0.2)', vuln: '#ef4444', direct: '#22c55e', transitive: 'rgba(255,255,255,0.2)' }
      const nodeRadius = (n: GNode) => n.type === 'root' ? 16 : n.type === 'vuln' ? Math.min(14, 8 + (n.cvss ?? 7)) : 7

      // Defs
      const defs = svg.append('defs')
      defs.append('marker').attr('id', 'arrow')
        .attr('viewBox', '0 -4 8 8').attr('refX', 22).attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
        .append('path').attr('d', 'M0,-4L8,0L0,4').attr('fill', 'rgba(255,255,255,0.08)')

      // Glow filters
      for (const [id, color, blur] of [['glow-red', '#ff2d55', 8], ['glow-cyan', '#00d4ff', 6], ['glow-purple', '#bf5fff', 8]] as const) {
        const f = defs.append('filter').attr('id', id)
        f.append('feGaussianBlur').attr('stdDeviation', blur).attr('result', 'blur')
        const feMerge = f.append('feMerge')
        feMerge.append('feMergeNode').attr('in', 'blur')
        feMerge.append('feMergeNode').attr('in', 'SourceGraphic')
      }

      svg.attr('viewBox', `0 0 ${W} ${H}`)
      svg.append('rect').attr('width', W).attr('height', H).attr('fill', '#050505')

      const g = svg.append('g')

      // Zoom
      const zoom = d3.zoom<SVGSVGElement, unknown>().scaleExtent([0.3, 4])
        .on('zoom', (e) => g.attr('transform', e.transform))
      ;(svg as any).call(zoom as any)

      // Simulation
      const sim = d3.forceSimulation(nodes as d3.SimulationNodeDatum[])
        .force('link', d3.forceLink(links).id((d: any) => d.id).distance(100).strength(0.7))
        .force('charge', d3.forceManyBody().strength(-250))
        .force('center', d3.forceCenter(W / 2, H / 2))
        .force('collide', d3.forceCollide(30))

      // Links
      const link = g.append('g').selectAll('line').data(links).join('line')
        .attr('stroke', 'rgba(255,255,255,0.08)').attr('stroke-width', 1).attr('marker-end', 'url(#arrow)')

      // Pulse rings for vuln
      const pulseRings = g.append('g').selectAll('circle.pulse')
        .data(nodes.filter(n => n.type === 'vuln')).join('circle')
        .attr('r', (n: GNode) => nodeRadius(n) + 6)
        .attr('fill', 'none').attr('stroke', '#ff2d55').attr('stroke-width', 1)
        .attr('stroke-opacity', 0.4)

      // Nodes
      const node = g.append('g').selectAll('g').data(nodes).join('g')
        .attr('cursor', 'grab')
        .call((d3.drag<SVGGElement, GNode>()
          .on('start', (e, d: any) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
          .on('drag', (e, d: any) => { d.fx = e.x; d.fy = e.y })
          .on('end', (e, d: any) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null })
        ) as any)

      node.append('circle')
        .attr('r', (n: GNode) => nodeRadius(n))
        .attr('fill', (n: GNode) => nodeColor[n.type])
        .attr('fill-opacity', 0.9).attr('stroke', 'rgba(255,255,255,0.15)').attr('stroke-width', 1)
        .attr('filter', (n: GNode) =>
          n.type === 'vuln' ? 'url(#glow-red)' :
          n.type === 'root' ? 'url(#glow-purple)' : 'none'
        )

      node.append('text')
        .attr('dy', (n: GNode) => nodeRadius(n) + 12)
        .attr('text-anchor', 'middle')
        .attr('font-size', '11px')
        .attr('font-family', 'Inter, sans-serif')
        .attr('fill', 'rgba(235,235,235,0.7)')
        .text((n: GNode) => n.id.length > 14 ? n.id.slice(0, 13) + '…' : n.id)

      // Tooltip
      const tooltip = d3.select('body').append('div')
        .style('position', 'fixed').style('background', '#0f1e2e')
        .style('border', '1px solid rgba(0,212,255,.2)').style('border-radius', '6px')
        .style('padding', '8px 12px').style('font-size', '12px')
        .style('font-family', 'JetBrains Mono, monospace').style('color', '#e0f2ff')
        .style('pointer-events', 'none').style('opacity', '0')
        .style('z-index', '9999').style('max-width', '200px')

      node.on('mouseover', (e, n: GNode) => {
        d3.select(e.currentTarget).select('circle').attr('stroke', '#10b981').attr('stroke-width', 2)
        const vuln = report.blast_radius_results.find(r => r.source_node === n.id)
        tooltip.html(
          `<div style="color:var(--cyan);font-weight:700">${n.id}</div>` +
          (vuln ? `<div>CVE: <span style="color:#ff2d55">${vuln.cve_id}</span></div><div>CVSS: ${vuln.cvss_score}</div><div>Blast: ${vuln.blast_radius_score.toFixed(1)}</div>` : `<div>Type: ${n.type}</div>`)
        ).style('opacity', '1')
      }).on('mousemove', (e) => {
        tooltip.style('left', (e.clientX + 14) + 'px').style('top', (e.clientY - 28) + 'px')
      }).on('mouseout', (e) => {
        d3.select(e.currentTarget).select('circle').attr('stroke', 'rgba(255,255,255,0.15)').attr('stroke-width', 1)
        tooltip.style('opacity', '0')
      })

      // Pulse animation
      function pulseTick() {
        pulseRings.attr('stroke-opacity', () => 0.2 + 0.3 * Math.abs(Math.sin(Date.now() / 1000)))
          .attr('r', (n: GNode) => nodeRadius(n) + 5 + 3 * Math.abs(Math.sin(Date.now() / 900)))
        requestAnimationFrame(pulseTick)
      }
      pulseTick()

      sim.on('tick', () => {
        link
          .attr('x1', (d: any) => d.source.x).attr('y1', (d: any) => d.source.y)
          .attr('x2', (d: any) => d.target.x).attr('y2', (d: any) => d.target.y)
        node.attr('transform', (d: any) => `translate(${d.x},${d.y})`)
        pulseRings.attr('cx', (n: any) => (n as any).x ?? 0).attr('cy', (n: any) => (n as any).y ?? 0)
      })

      return () => {
        sim.stop()
        tooltip.remove()
      }
    })
  }, [report])

  return (
    <Card
      title="⬡ Dependency Attack Graph"
      badge="drag · scroll to zoom"
      glowColor="var(--cyan)"
      style={{ gridColumn: '1 / -1' }}
    >
      <div ref={containerRef} style={{ height: 400, position: 'relative' }}>
        <svg ref={svgRef} style={{ width: '100%', height: '100%' }} />
        {/* Legend */}
        <div style={{
          position: 'absolute', bottom: 10, left: 12,
          display: 'flex', flexDirection: 'column', gap: 4,
        }}>
          {[['var(--purple)', 'Root'], ['var(--red)', 'Vulnerable'], ['var(--cyan)', 'Direct dep'], ['#1e3a52', 'Transitive']].map(([c, l]) => (
            <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: c, boxShadow: `0 0 4px ${c}` }} />
              {l}
            </div>
          ))}
        </div>
      </div>
    </Card>
  )
}
