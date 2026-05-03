import { BlastRadiusResult, PatchRecommendation, ScanReport } from './types'

export interface AISecuritySummary {
  title: string
  tone: string
  body: string
  stats: Array<{ label: string; value: string }>
}

export interface AIChatPrompt {
  question: string
  answer: string
}

export interface GlossaryItem {
  term: string
  detail: string
}

const CONFIDENCE_ORDER: Record<string, number> = {
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
}

function formatCount(value: number, noun: string): string {
  return `${value} ${noun}${value === 1 ? '' : 's'}`
}

function toRiskTone(risk: ScanReport['risk_summary']): string {
  if (risk === 'CRITICAL' || risk === 'HIGH') return 'Immediate action recommended'
  if (risk === 'MEDIUM') return 'Prioritize the vulnerable packages this week'
  if (risk === 'LOW') return 'Low urgency, but still worth patching'
  return 'No immediate security blockers detected'
}

function buildFallbackRecommendation(result: BlastRadiusResult, report: ScanReport): PatchRecommendation {
  const ecosystem = report.ecosystem
  const upgradeCommand =
    ecosystem === 'npm'
      ? `npm install ${result.source_node}@latest`
      : ecosystem === 'pip'
        ? `pip install --upgrade ${result.source_node}`
        : `upgrade ${result.source_node} to the latest safe release`

  const sinkSummary = result.sink_types.length
    ? `${result.sink_types.join(' and ')} sinks`
    : 'application code'

  const confidence: PatchRecommendation['confidence'] =
    result.cvss_score >= 9
      ? 'HIGH'
      : result.cvss_score >= 7
        ? 'MEDIUM'
        : 'LOW'

  return {
    package_name: result.source_node,
    current_version: 'detected in graph',
    cve_ids: result.cve_id ? [result.cve_id] : [],
    cvss_score: result.cvss_score,
    recommended_version: 'latest',
    threat_explanation: `${result.source_node} is exposed to ${result.cve_id || 'a known vulnerability'} with CVSS ${result.cvss_score.toFixed(1)}. It can reach ${formatCount(result.reachable_count, 'downstream package')} including ${sinkSummary}. This makes it one of the highest-priority fixes in this scan.`,
    breaking_changes: 'Review changelog before rollout.',
    upgrade_command: upgradeCommand,
    confidence,
    attack_path_summary: result.attack_paths[0]
      ? result.attack_paths[0].path.join(' -> ')
      : `Attacker exploits ${result.source_node} to reach ${sinkSummary}.`,
    blast_radius_score: result.blast_radius_score,
  }
}

export function buildPatchRecommendations(report: ScanReport): PatchRecommendation[] {
  const merged = new Map<string, PatchRecommendation>()

  for (const rec of report.patch_recommendations) {
    merged.set(rec.package_name, rec)
  }

  for (const result of report.blast_radius_results) {
    if (!merged.has(result.source_node)) {
      merged.set(result.source_node, buildFallbackRecommendation(result, report))
    }
  }

  return [...merged.values()]
    .sort((a, b) => {
      const blastDelta = (b.blast_radius_score || 0) - (a.blast_radius_score || 0)
      if (blastDelta !== 0) return blastDelta
      const confDelta =
        (CONFIDENCE_ORDER[b.confidence] || 0) - (CONFIDENCE_ORDER[a.confidence] || 0)
      if (confDelta !== 0) return confDelta
      return b.cvss_score - a.cvss_score
    })
    .slice(0, 10)
}

export function buildSecuritySummary(report: ScanReport): AISecuritySummary {
  const top = report.blast_radius_results[0]
  const bodyParts = [
    `Your project (${formatCount(report.total_packages, 'package')}) has ${formatCount(report.vulnerable_packages, 'vulnerable dependency')}.`,
    report.critical_count > 0 ? `That includes ${formatCount(report.critical_count, 'critical CVE')}.` : `No critical CVEs were detected.`,
  ]

  if (top) {
    bodyParts.push(
      `The highest-risk package is ${top.source_node} with a blast radius of ${top.blast_radius_score.toFixed(1)}, reaching ${formatCount(top.reachable_count, 'downstream package')}.`
    )
  }

  if (report.circular_trust_clusters.length > 0) {
    bodyParts.push(
      `${formatCount(report.circular_trust_clusters.length, 'circular trust chain')} still needs review.`
    )
  } else {
    bodyParts.push('No circular trust chains were detected, which is a positive signal.')
  }

  if (report.minimum_patch_set.packages_to_update_count > 0) {
    bodyParts.push(
      `The minimum patch set suggests updating ${formatCount(report.minimum_patch_set.packages_to_update_count, 'package')} to eliminate ${formatCount(report.minimum_patch_set.attack_paths_eliminated, 'known attack path')}, saving ${Math.round(report.minimum_patch_set.savings_percent)}% of patch effort.`
    )
  }

  const highestPriority = buildPatchRecommendations(report)
    .slice(0, 3)
    .map((rec) => rec.package_name)
    .join(', ')

  if (highestPriority) {
    bodyParts.push(`Immediate attention should go to ${highestPriority}.`)
  }

  return {
    title: `${report.risk_summary === 'CRITICAL' ? 'Critical risk' : report.risk_summary === 'HIGH' ? 'High risk' : report.risk_summary === 'MEDIUM' ? 'Elevated risk' : report.risk_summary === 'LOW' ? 'Low risk' : 'Clean scan'}`,
    tone: toRiskTone(report.risk_summary),
    body: bodyParts.join(' '),
    stats: [
      { label: 'critical CVEs', value: String(report.critical_count) },
      { label: 'top blast radius', value: top ? `${top.source_node} ${top.blast_radius_score.toFixed(1)}` : 'n/a' },
      { label: 'circular chains', value: String(report.circular_trust_clusters.length) },
      { label: 'minimum fix set', value: String(report.minimum_patch_set.packages_to_update_count) },
      { label: 'effort saved', value: `${Math.round(report.minimum_patch_set.savings_percent)}%` },
    ],
  }
}

export const GLOSSARY: GlossaryItem[] = [
  {
    term: 'Blast radius',
    detail: 'How many packages become reachable if a vulnerable package is exploited. Bigger blast radius means a compromise spreads further through the graph.',
  },
  {
    term: 'Circular trust chain',
    detail: 'A cycle like A -> B -> C -> A. If one package in the cycle is compromised, trust spreads across the whole loop.',
  },
  {
    term: 'Steiner tree / minimum patch set',
    detail: 'A graph algorithm that finds the smallest set of packages to update that eliminates the known attack paths in the scan.',
  },
  {
    term: 'Topological risk score',
    detail: 'CVSS amplified by graph position. A package depended on by many others becomes more dangerous than an isolated one with the same CVSS.',
  },
]

export function buildChatPrompts(report: ScanReport): AIChatPrompt[] {
  const recommendations = buildPatchRecommendations(report)
  const top = report.blast_radius_results[0]
  const firstFix = report.minimum_patch_set.update_order[0] || recommendations[0]?.package_name || 'the top vulnerable package'
  const riskyPackages = recommendations.slice(0, 5).map((rec) => rec.package_name).join(', ')

  return [
    {
      question: 'Is my project safe to deploy?',
      answer:
        report.critical_count > 0 || report.risk_summary === 'HIGH' || report.risk_summary === 'CRITICAL'
          ? `Not yet. This scan shows ${formatCount(report.critical_count, 'critical CVE')} across ${formatCount(report.vulnerable_packages, 'vulnerable dependency')}. The fastest path to reduce risk is the minimum patch set: ${report.minimum_patch_set.update_order.join(' -> ') || riskyPackages}.`
          : `It is in much better shape than a typical dependency graph. There are no critical blockers in this scan, but I would still patch ${riskyPackages || 'the remaining low-risk packages'} before the next release window.`,
    },
    {
      question: `Why is ${top?.source_node || 'the top package'} so dangerous here?`,
      answer: top
        ? `${top.source_node} has the highest blast radius in this scan at ${top.blast_radius_score.toFixed(1)}. It reaches ${formatCount(top.reachable_count, 'downstream package')} and touches ${top.sink_types.length ? top.sink_types.join(' and ') : 'application'} sinks, which makes exploitation spread far beyond the vulnerable package itself.`
        : 'This scan does not show a dominant high-blast package, so patching order should follow CVSS severity and direct exposure.',
    },
    {
      question: 'Which package should I fix first?',
      answer: `Start with ${firstFix}. It sits at the front of the minimum patch set and contributes the most immediate risk reduction for this scan.`,
    },
    {
      question: 'Explain minimum patch set',
      answer: `Instead of upgrading every vulnerable dependency, GraphShield finds the smallest set of packages that breaks every known attack path. In this scan that means ${formatCount(report.minimum_patch_set.packages_to_update_count, 'package')} instead of ${formatCount(report.vulnerable_packages, 'package')}, saving ${Math.round(report.minimum_patch_set.savings_percent)}% of the update effort.`,
    },
  ]
}

export function buildPrDescription(report: ScanReport): string {
  const headingCount = report.minimum_patch_set.packages_to_update_count || report.vulnerable_packages
  return [
    `## GraphShield Security Patch - ${headingCount} packages`,
    '',
    `Eliminates ${formatCount(report.vulnerable_packages, 'known vulnerable dependency')} including ${formatCount(report.critical_count, 'critical CVE')}.`,
    `Steiner Tree minimum patch set selected ${headingCount} package(s), reducing patch effort by ${Math.round(report.minimum_patch_set.savings_percent)}%.`,
    '',
    `**Update order:** ${report.minimum_patch_set.update_order.join(' -> ') || 'Review top vulnerabilities'}`,
    `**Attack paths eliminated:** ${report.minimum_patch_set.attack_paths_eliminated || 0}`,
    `**Effort:** ${report.minimum_patch_set.estimated_effort}`,
    '',
    '### Priority packages',
    ...buildPatchRecommendations(report)
      .slice(0, 5)
      .map((rec) => `- ${rec.package_name}: ${rec.upgrade_command}`),
  ].join('\n')
}
