import { useState, useCallback, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { DEMO_REPORT } from '../demoData'
import { checkHealth, runScan } from '../api'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
interface UploadZoneProps { onLoad: (report: any) => void }

type Tab = 'file' | 'scan'

export default function UploadZone({ onLoad }: UploadZoneProps) {
  const [dragging, setDragging] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('file')
  const [scanTarget, setScanTarget] = useState('')
  const [scanning, setScanning] = useState(false)
  const [apiOnline, setApiOnline] = useState<boolean | null>(null)

  // Check API health on mount
  useEffect(() => {
    checkHealth().then(setApiOnline)
  }, [])

  const parse = useCallback((file: File) => {
    setError(null)
    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const json = JSON.parse(e.target?.result as string)
        onLoad(json)
      } catch {
        setError('Invalid JSON — generate with: graphshield scan . --output report.json')
      }
    }
    reader.readAsText(file)
  }, [onLoad])

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault(); setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) parse(file)
  }

  const onInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) parse(file)
  }

  const handleLiveScan = async () => {
    if (!scanTarget.trim()) { setError('Enter a path or GitHub URL'); return }
    setError(null); setScanning(true)
    try {
      const report = await runScan({ target: scanTarget.trim() })
      onLoad(report)
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : 'Scan failed'
      )
    } finally {
      setScanning(false)
    }
  }

  const tabStyle = (active: boolean): React.CSSProperties => ({
    padding: '6px 20px',
    borderRadius: 'var(--radius-sm)',
    background: active ? 'rgba(0,212,255,.12)' : 'transparent',
    color: active ? 'var(--cyan)' : 'var(--text-muted)',
    border: active ? '1px solid rgba(0,212,255,.25)' : '1px solid transparent',
    cursor: 'pointer',
    fontFamily: 'var(--font-mono)',
    fontSize: '.75rem',
    fontWeight: 700,
    letterSpacing: '.08em',
    transition: 'all .15s',
  })

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', minHeight: '100vh', gap: 28, padding: 24,
    }}>
      {/* ── Brand ── */}
      <motion.div initial={{ opacity: 0, y: -24 }} animate={{ opacity: 1, y: 0 }} style={{ textAlign: 'center' }}>
        <div style={{
          fontFamily: 'var(--font-display)',
          fontSize: 'clamp(2.2rem, 5vw, 3.8rem)',
          fontWeight: 900, letterSpacing: '.06em',
          background: 'linear-gradient(120deg, var(--cyan) 0%, var(--purple) 50%, var(--cyan) 100%)',
          backgroundSize: '200% auto',
          WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
          animation: 'flicker 8s infinite',
          filter: 'drop-shadow(0 0 24px rgba(0,212,255,.28))',
        }}>
          GRAPH<span style={{ WebkitTextFillColor: 'var(--red)', filter: 'drop-shadow(0 0 12px rgba(255,45,85,.4))' }}>SHIELD</span>
        </div>
        <div style={{ color: 'var(--text-secondary)', fontSize: '.85rem', marginTop: 6, letterSpacing: '.22em', textTransform: 'uppercase' }}>
          Vulnerability Intelligence Engine
        </div>

        {/* API status indicator */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, marginTop: 10 }}>
          <div style={{
            width: 7, height: 7, borderRadius: '50%',
            background: apiOnline === null ? 'var(--text-muted)' : apiOnline ? 'var(--green)' : 'var(--red)',
            boxShadow: apiOnline ? '0 0 8px var(--green)' : apiOnline === false ? '0 0 8px var(--red)' : 'none',
          }} />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '.68rem', color: 'var(--text-muted)' }}>
            API {apiOnline === null ? 'checking…' : apiOnline ? 'online :8000' : 'offline — file upload only'}
          </span>
        </div>
      </motion.div>

      {/* ── Tabs ── */}
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: .1 }}
        style={{ display: 'flex', gap: 4 }}>
        <button style={tabStyle(tab === 'file')} onClick={() => setTab('file')}>⬆ UPLOAD JSON</button>
        <button style={tabStyle(tab === 'scan')} onClick={() => setTab('scan')}>⚡ LIVE SCAN</button>
      </motion.div>

      {/* ── Upload tab ── */}
      <AnimatePresence mode="wait">
        {tab === 'file' && (
          <motion.div key="file" initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 10 }}
            style={{ width: '100%', maxWidth: 520 }}>
            <div
              onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              onClick={() => document.getElementById('file-input')?.click()}
              style={{
                padding: '44px 40px',
                border: `2px dashed ${dragging ? 'var(--cyan)' : 'rgba(0,212,255,.18)'}`,
                borderRadius: 'var(--radius-xl)',
                background: dragging ? 'rgba(0,212,255,.04)' : 'var(--bg-surface)',
                cursor: 'pointer', transition: 'all .2s', textAlign: 'center',
                boxShadow: dragging ? '0 0 40px rgba(0,212,255,.12), inset 0 0 40px rgba(0,212,255,.04)' : 'inset 0 0 0 1px rgba(0,212,255,.06)',
              }}
            >
              <div style={{ fontSize: 42, marginBottom: 10 }}>{dragging ? '📡' : '📂'}</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '.9rem', color: 'var(--text-primary)', fontWeight: 600 }}>
                Drop scan report here
              </div>
              <div style={{ color: 'var(--text-muted)', fontSize: '.78rem', marginTop: 5 }}>
                or click to browse · <span style={{ color: 'var(--cyan)' }}>report.json</span>
              </div>
              <input id="file-input" type="file" accept=".json" style={{ display: 'none' }} onChange={onInput} />
            </div>
          </motion.div>
        )}

        {tab === 'scan' && (
          <motion.div key="scan" initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -10 }}
            style={{ width: '100%', maxWidth: 520, display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-lg)', overflow: 'hidden',
            }}>
              <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border-subtle)', fontFamily: 'var(--font-mono)', fontSize: '.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.1em' }}>
                Scan target
              </div>
              <input
                value={scanTarget}
                onChange={e => setScanTarget(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleLiveScan()}
                placeholder="./my-project  or  https://github.com/user/repo"
                disabled={!apiOnline || scanning}
                style={{
                  width: '100%', padding: '14px 16px',
                  background: 'transparent', border: 'none', outline: 'none',
                  color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: '.85rem',
                  caretColor: 'var(--cyan)',
                }}
              />
            </div>
            <button
              onClick={handleLiveScan}
              disabled={!apiOnline || scanning}
              style={{
                padding: '12px', borderRadius: 'var(--radius)',
                background: (!apiOnline || scanning) ? 'var(--bg-elevated)' : 'var(--cyan)',
                color: (!apiOnline || scanning) ? 'var(--text-muted)' : 'var(--bg-void)',
                border: 'none', cursor: (!apiOnline || scanning) ? 'not-allowed' : 'pointer',
                fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '.85rem',
                letterSpacing: '.05em', transition: 'all .15s',
                boxShadow: (!apiOnline || scanning) ? 'none' : '0 0 20px rgba(0,212,255,.25)',
              }}
            >
              {scanning ? '⟳ SCANNING…' : !apiOnline ? '✗ API OFFLINE — START api_server.py' : '⚡ RUN SCAN'}
            </button>
            {!apiOnline && (
              <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', padding: '10px 14px', fontFamily: 'var(--font-mono)', fontSize: '.72rem', color: 'var(--text-muted)' }}>
                <span style={{ color: 'var(--green)' }}>$</span> python api_server.py
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Demo button ── */}
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: .3 }}
        style={{ display: 'flex', gap: 10, flexWrap: 'wrap', justifyContent: 'center' }}>
        <button
          onClick={() => document.getElementById('file-input')?.click()}
          style={{
            padding: '9px 22px', borderRadius: 'var(--radius)',
            background: 'var(--cyan)', color: 'var(--bg-void)',
            border: 'none', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '.78rem',
            letterSpacing: '.05em', boxShadow: '0 0 16px rgba(0,212,255,.25)', transition: 'all .15s',
          }}
          onMouseEnter={e => (e.currentTarget.style.boxShadow = '0 0 28px rgba(0,212,255,.5)')}
          onMouseLeave={e => (e.currentTarget.style.boxShadow = '0 0 16px rgba(0,212,255,.25)')}
        >
          ⟨ LOAD REPORT ⟩
        </button>
        <button
          onClick={() => onLoad(DEMO_REPORT)}
          style={{
            padding: '9px 22px', borderRadius: 'var(--radius)',
            background: 'transparent', color: 'var(--text-secondary)',
            border: '1px solid var(--border)', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '.78rem',
            letterSpacing: '.05em', transition: 'all .15s',
          }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--purple)'; e.currentTarget.style.color = 'var(--purple)' }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-secondary)' }}
        >
          ⟨ DEMO MODE ⟩
        </button>
      </motion.div>

      {/* ── Error ── */}
      <AnimatePresence>
        {error && (
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            style={{ color: 'var(--red)', fontFamily: 'var(--font-mono)', fontSize: '.78rem', textAlign: 'center', maxWidth: 480 }}>
            ⚠ {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── CLI hint ── */}
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: .5 }}
        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius)', padding: '10px 18px', fontFamily: 'var(--font-mono)', fontSize: '.73rem', color: 'var(--text-muted)' }}>
        <span style={{ color: 'var(--green)' }}>$</span>{' '}
        <span style={{ color: 'var(--cyan)' }}>graphshield</span> scan . --output report.json
      </motion.div>
    </div>
  )
}
