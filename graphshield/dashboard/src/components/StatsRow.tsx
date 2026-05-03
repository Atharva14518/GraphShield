import { ScanReport } from '../types'
import { StatCard } from './UI'

interface StatsRowProps { report: ScanReport }

export default function StatsRow({ report: r }: StatsRowProps) {
  const clean = r.total_packages - r.vulnerable_packages

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
      gap: 10, marginBottom: 16,
    }}>
      <StatCard label="Packages" value={r.total_packages} sub={r.ecosystem} />
      <StatCard
        label="Vulnerable" value={r.vulnerable_packages}
        sub={`${clean} clean`}
        color={r.vulnerable_packages > 0 ? 'var(--red)' : 'var(--green)'}
        glow={r.vulnerable_packages > 0}
      />
      <StatCard
        label="Critical" value={r.critical_count}
        sub="CVSS ≥ 9.0"
        color={r.critical_count > 0 ? 'var(--red)' : 'var(--text-muted)'}
        glow={r.critical_count > 0}
      />
      <StatCard
        label="High" value={r.high_count}
        sub="CVSS 7–9"
        color={r.high_count > 0 ? 'var(--orange)' : 'var(--text-muted)'}
      />
      <StatCard
        label="Medium" value={r.medium_count ?? 0}
        sub="CVSS 4–7"
        color={(r.medium_count ?? 0) > 0 ? 'var(--yellow)' : 'var(--text-muted)'}
      />
      <StatCard
        label="Clusters" value={r.circular_trust_clusters.length}
        sub="circular SCCs"
        color={r.circular_trust_clusters.length > 0 ? 'var(--purple)' : 'var(--text-muted)'}
      />
      <StatCard
        label="Min. Updates"
        value={`${r.minimum_patch_set.packages_to_update_count}/${r.vulnerable_packages}`}
        sub={`${r.minimum_patch_set.savings_percent.toFixed(0)}% savings`}
        color="var(--cyan)"
      />
    </div>
  )
}
