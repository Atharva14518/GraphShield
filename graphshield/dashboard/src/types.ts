// Type definitions for GraphShield scan reports

export interface AttackPath {
  path: string[];
  sink_type: string;
  sink_node: string;
  path_length: number;
  exploit_score: number;
  exploitability: string;
}

export interface BlastRadiusResult {
  source_node: string;
  cve_id: string;
  cvss_score: number;
  reachable_nodes: string[];
  reachable_count: number;
  sensitive_sinks_reachable: string[];
  sink_types: string[];
  data_sensitivity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  blast_radius_score: number;
  attack_paths: AttackPath[];
  topological_rank: number | null;
}

export interface CircularTrustCluster {
  nodes: string[];
  size: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  max_cvss_in_cluster: number;
  combined_blast_radius: number;
}

export interface MinimumPatchSet {
  packages_to_update: string[];
  packages_to_update_count: number;
  total_vulnerable_count: number;
  attack_paths_eliminated: number;
  savings_percent: number;
  update_order: string[];
  estimated_effort: 'LOW' | 'MEDIUM' | 'HIGH';
  reasoning: string;
}

export interface PatchRecommendation {
  package_name: string;
  current_version: string;
  cve_ids: string[];
  cvss_score: number;
  recommended_version: string;
  threat_explanation: string;
  breaking_changes: string;
  upgrade_command: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  attack_path_summary: string;
  blast_radius_score: number;
}

export interface ScanReport {
  manifest_path: string;
  target: string;
  ecosystem: string;
  total_packages: number;
  vulnerable_packages: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  circular_trust_clusters: CircularTrustCluster[];
  blast_radius_results: BlastRadiusResult[];
  minimum_patch_set: MinimumPatchSet;
  patch_recommendations: PatchRecommendation[];
  scan_duration_seconds: number;
  timestamp: string;
  risk_summary: 'CLEAN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export type RiskLevel = 'CLEAN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
