import { useEffect, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { ScanReport } from './types'
import { buildPatchRecommendations } from './ai'
import UploadZone from './components/UploadZone'
import Header from './components/Header'
import StatsRow from './components/StatsRow'
import VulnTable from './components/VulnTable'
import RiskChart from './components/RiskChart'
import DependencyGraph from './components/DependencyGraph'
import AttackPathViewer from './components/AttackPathViewer'
import PatchSet from './components/PatchSet'
import AIPatchPanel from './components/AIPatchPanel'
import AISecuritySummary from './components/AISecuritySummary'
import AIExplainerPanel from './components/AIExplainerPanel'
import AIChatPanel from './components/AIChatPanel'
import PRDescriptionGenerator from './components/PRDescriptionGenerator'
import SCCPanel from './components/SCCPanel'

/** Ensure all optional fields exist so components never crash on undefined. */
function normalizeReport(raw: Record<string, unknown>): ScanReport {
  return {
    manifest_path: String(raw.manifest_path ?? ''),
    target: String(raw.target ?? 'unknown'),
    ecosystem: String(raw.ecosystem ?? 'unknown'),
    total_packages: Number(raw.total_packages ?? 0),
    vulnerable_packages: Number(raw.vulnerable_packages ?? 0),
    critical_count: Number(raw.critical_count ?? 0),
    high_count: Number(raw.high_count ?? 0),
    medium_count: Number(raw.medium_count ?? 0),
    risk_summary: (raw.risk_summary as ScanReport['risk_summary']) ?? 'CLEAN',
    scan_duration_seconds: Number(raw.scan_duration_seconds ?? 0),
    timestamp: String(raw.timestamp ?? new Date().toISOString()),
    circular_trust_clusters: Array.isArray(raw.circular_trust_clusters) ? raw.circular_trust_clusters : [],
    blast_radius_results: Array.isArray(raw.blast_radius_results) ? raw.blast_radius_results : [],
    minimum_patch_set: (raw.minimum_patch_set as ScanReport['minimum_patch_set']) ?? {
      packages_to_update: [], packages_to_update_count: 0,
      total_vulnerable_count: 0, attack_paths_eliminated: 0,
      savings_percent: 0, update_order: [], estimated_effort: 'LOW', reasoning: '',
    },
    patch_recommendations: Array.isArray(raw.patch_recommendations) ? raw.patch_recommendations : [],
  } as ScanReport
}

export default function App() {
  const [report, setReport] = useState<ScanReport | null>(null)
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => entries.forEach((entry) => entry.target.classList.toggle('is-visible', entry.isIntersecting)),
      { threshold: 0.1 }
    )
    document.querySelectorAll('.reveal').forEach((el, idx) => {
      ;(el as HTMLElement).style.transitionDelay = `${idx * 100}ms`
      observer.observe(el)
    })
    return () => observer.disconnect()
  }, [report])

  const loadReport = (raw: Record<string, unknown>) => setReport(normalizeReport(raw))

  const gridStyle: React.CSSProperties = {
    display: 'grid',
    gap: 12,
  }

  const aiRecommendations = report ? buildPatchRecommendations(report) : []

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-void)' }}>
      <AnimatePresence mode="wait">
        {!report ? (
          <motion.div key="upload"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0, scale: .98 }}
            transition={{ duration: .25 }}
          >
            <UploadZone onLoad={(raw) => loadReport(raw)} />
          </motion.div>
        ) : (
          <motion.div key="dashboard"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            transition={{ duration: .3 }}
          >
            <Header report={report} onReset={() => setReport(null)} />

            <div style={{ padding: '84px 20px 48px', maxWidth: 1600, margin: '0 auto' }}>
              <section className="reveal" style={{ marginBottom: 32, display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 24 }}>
                <div>
                  <div style={{ fontFamily: 'var(--font-label)', fontSize: 10, letterSpacing: '.2em', textTransform: 'uppercase', color: 'rgba(235,235,235,.6)', display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                    <span style={{ width: 8, height: 8, borderRadius: 999, background: '#10b981', animation: 'pulse 1.5s infinite' }} />
                    Vulnerability Intelligence Engine
                  </div>
                  <h1 style={{ fontFamily: 'var(--font-display)', fontWeight: 200, letterSpacing: '-0.03em', lineHeight: 0.95, fontSize: 'clamp(48px, 6vw, 96px)', marginBottom: 14 }}>
                    Graph-native<br />security<br />intelligence.
                  </h1>
                  <p style={{ maxWidth: 480, fontFamily: 'Inter', fontWeight: 300, color: 'rgba(235,235,235,0.5)', fontSize: 16, marginBottom: 18 }}>
                    Models your supply chain as a directed graph. Finds circular trust chains, blast radii, and minimum patch sets no flat scanner can detect.
                  </p>
                  <div style={{ display: 'flex', gap: 12 }}>
                    <button style={{ borderRadius: 999, padding: '10px 28px', border: '1px solid #fff', background: '#fff', color: '#000' }}>Run Scan</button>
                    <button style={{ borderRadius: 999, padding: '10px 28px', border: '1px solid rgba(255,255,255,0.3)', background: 'transparent', color: '#EBEBEB' }}>View Docs</button>
                  </div>
                </div>
              </section>

              {/* ── Stats ── */}
              <motion.div
                className="reveal"
                initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: .05 }}
              >
                <StatsRow report={report} />
              </motion.div>

              <motion.div
                className="reveal"
                initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: .08 }}
                style={{ marginBottom: 12 }}
              >
                <AISecuritySummary report={report} />
              </motion.div>

              {/* ── Vuln + Risk Chart ── */}
              <motion.div
                className="reveal"
                initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: .12 }}
                style={{ ...gridStyle, gridTemplateColumns: '1fr 280px', marginBottom: 12 }}
              >
                <VulnTable results={report.blast_radius_results} />
                <RiskChart report={report} />
              </motion.div>

              {/* ── Force Graph ── */}
              <motion.div
                className="reveal"
                initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: .2 }}
                style={{ marginBottom: 12 }}
              >
                <DependencyGraph report={report} />
              </motion.div>

              {/* ── Attack Paths + Patch Set ── */}
              <motion.div
                className="reveal"
                initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: .28 }}
                style={{ ...gridStyle, gridTemplateColumns: '1fr 1fr', marginBottom: 12 }}
              >
                <AttackPathViewer results={report.blast_radius_results} />
                <PatchSet mps={report.minimum_patch_set} results={report.blast_radius_results} />
              </motion.div>

              {/* ── AI Patch Intelligence ── */}
              <motion.div
                className="reveal"
                initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: .32 }}
              >
                <AIPatchPanel patch_recommendations={aiRecommendations} />
              </motion.div>

              <motion.div
                className="reveal"
                initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: .34 }}
                style={{ ...gridStyle, gridTemplateColumns: '0.9fr 1.1fr', marginBottom: 12 }}
              >
                <AIExplainerPanel />
                <PRDescriptionGenerator report={report} />
              </motion.div>

              {/* ── SCC ── */}
              <motion.div
                className="reveal"
                initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: .35 }}
              >
                <SCCPanel clusters={report.circular_trust_clusters} />
              </motion.div>

              <section className="reveal" style={{ marginTop: 40, padding: '120px 0', textAlign: 'center' }}>
                <h2 style={{
                  fontFamily: 'var(--font-display)',
                  fontSize: 'clamp(40px,5vw,80px)',
                  fontWeight: 200,
                  background: 'linear-gradient(90deg, #EBEBEB 0%, #10b981 50%, #EBEBEB 100%)',
                  backgroundSize: '200% auto',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                  animation: 'gradientShift 4s linear infinite',
                }}>Secure the graph before it breaks prod.</h2>
                <p style={{ fontFamily: 'Inter', fontWeight: 300, color: 'rgba(235,235,235,0.4)', margin: '8px 0 18px' }}>Graph-first dependency intelligence for CI-grade patch decisions.</p>
                <button style={{ borderRadius: 999, padding: '10px 28px', border: '1px solid #fff', background: '#fff', color: '#000', animation: 'pulse-glow 2s infinite' }}>Run Scan</button>
              </section>
            </div>
            <AIChatPanel report={report} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
