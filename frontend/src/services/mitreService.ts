import { AxiosInstance } from 'axios';

export interface MitreTactic {
  id: string;
  name: string;
  description: string;
  short_name: string;
  url?: string;
  created_at?: string;
  updated_at?: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  platforms?: string[];
  data_sources?: string[];
  sub_techniques?: string[];
  url?: string;
  detection?: string;
  created_at?: string;
  updated_at?: string;
}

export interface TacticCoverage {
  tactic_id: string;
  tactic_name: string;
  total_rules: number;
  total_alerts: number;
  last_alert_time?: string;
}

export interface TechniqueCoverage {
  technique_id: string;
  technique_name: string;
  total_rules: number;
  total_alerts: number;
  last_alert_time?: string;
}

export interface MitreStatistics {
  total_tactics: number;
  total_techniques: number;
  total_groups: number;
  total_software: number;
  total_mitigations: number;
  framework_version?: string;
}

export interface NavigatorLayer {
  name: string;
  description: string;
  domain: string;
  version: string;
  techniques: NavigatorTechnique[];
}

export interface NavigatorTechnique {
  techniqueID: string;
  score: number;
  color?: string;
  comment?: string;
}

export interface TechniqueAnalytics {
  technique_id: string;
  technique_name: string;
  rule_count: number;
  alert_count_30d: number;
  last_seen?: string;
  coverage: number; // 0-100
}

export interface TacticAnalytics {
  tactic_id: string;
  tactic_name: string;
  total_techniques: number;
  covered_techniques: number;
  gap_count: number;
  rule_count: number;
  alert_count_30d: number;
  coverage_percent: number;
}

export interface CoverageGap {
  technique_id: string;
  technique_name: string;
  tactics: string[];
}

export interface CoverageReport {
  total_techniques: number;
  covered_techniques: number;
  coverage_percent: number;
  tactic_coverage: TacticAnalytics[];
  coverage_gaps: CoverageGap[];
  last_updated: string;
}

export interface MatrixTechnique {
  id: string;
  name: string;
  rule_count: number;
  coverage: 'none' | 'partial' | 'full';
}

export interface MatrixTactic {
  id: string;
  name: string;
  short_name: string;
  techniques: MatrixTechnique[];
}

export interface MatrixView {
  platform: string;
  tactics: MatrixTactic[];
}

export interface CoverageMatrix {
  tactics: Array<{
    tactic_id: string;
    tactic_name: string;
    techniques: Array<{
      technique_id: string;
      technique_name: string;
      is_covered: boolean;
      rule_count: number;
    }>;
  }>;
}

/**
 * MITRE ATT&CK service for accessing framework data
 */
class MitreService {
  constructor(private api: AxiosInstance) {}

  /**
   * Get framework statistics
   */
  async getStatistics(): Promise<MitreStatistics> {
    const response = await this.api.get('/mitre/statistics');
    return response.data;
  }

  /**
   * Get all tactics
   */
  async getTactics(): Promise<MitreTactic[]> {
    const response = await this.api.get('/mitre/tactics');
    return response.data;
  }

  /**
   * Get a single tactic by ID
   */
  async getTactic(id: string): Promise<MitreTactic> {
    const response = await this.api.get(`/mitre/tactics/${id}`);
    return response.data;
  }

  /**
   * Get techniques with optional filtering
   */
  async getTechniques(params?: {
    limit?: number;
    offset?: number;
    tactic_id?: string;
  }): Promise<{
    items: MitreTechnique[];
    total: number;
    page: number;
    limit: number;
    total_pages: number;
  }> {
    const queryParams = new URLSearchParams();

    if (params?.limit) queryParams.append('limit', params.limit.toString());
    if (params?.offset) queryParams.append('offset', params.offset.toString());
    if (params?.tactic_id) queryParams.append('tactic_id', params.tactic_id);

    const response = await this.api.get(`/mitre/techniques?${queryParams.toString()}`);
    return response.data;
  }

  /**
   * Get a single technique by ID
   */
  async getTechnique(id: string): Promise<MitreTechnique> {
    const response = await this.api.get(`/mitre/techniques/${id}`);
    return response.data;
  }

  /**
   * Search techniques by name or ID
   */
  async searchTechniques(query: string, limit = 20): Promise<MitreTechnique[]> {
    const response = await this.api.get('/mitre/techniques/search', {
      params: { q: query, limit },
    });
    return response.data;
  }

  /**
   * Get tactic coverage statistics
   */
  async getTacticCoverage(): Promise<TacticCoverage[]> {
    const response = await this.api.get('/mitre/coverage/tactics');
    return response.data;
  }

  /**
   * Get technique coverage statistics
   */
  async getTechniqueCoverage(): Promise<TechniqueCoverage[]> {
    const response = await this.api.get('/mitre/coverage/techniques');
    return response.data;
  }

  /**
   * Generate ATT&CK Navigator layer from current detections
   */
  async generateNavigatorLayer(params?: {
    start_date?: string;
    end_date?: string;
    severity_filter?: string[];
  }): Promise<NavigatorLayer> {
    const response = await this.api.post('/mitre/navigator/generate', params || {});
    return response.data;
  }

  /**
   * Get threat groups
   */
  async getGroups(params?: {
    limit?: number;
    offset?: number;
  }): Promise<{
    groups: any[];
    total: number;
  }> {
    const queryParams = new URLSearchParams();
    if (params?.limit) queryParams.append('limit', params.limit.toString());
    if (params?.offset) queryParams.append('offset', params.offset.toString());

    const response = await this.api.get(`/mitre/groups?${queryParams.toString()}`);
    return response.data;
  }

  /**
   * Get software (malware and tools)
   */
  async getSoftware(params?: {
    limit?: number;
    offset?: number;
  }): Promise<{
    software: any[];
    total: number;
  }> {
    const queryParams = new URLSearchParams();
    if (params?.limit) queryParams.append('limit', params.limit.toString());
    if (params?.offset) queryParams.append('offset', params.offset.toString());

    const response = await this.api.get(`/mitre/software?${queryParams.toString()}`);
    return response.data;
  }

  /**
   * Get mitigations
   */
  async getMitigations(params?: {
    limit?: number;
    offset?: number;
  }): Promise<{
    mitigations: any[];
    total: number;
  }> {
    const queryParams = new URLSearchParams();
    if (params?.limit) queryParams.append('limit', params.limit.toString());
    if (params?.offset) queryParams.append('offset', params.offset.toString());

    const response = await this.api.get(`/mitre/mitigations?${queryParams.toString()}`);
    return response.data;
  }

  /**
   * Get ATT&CK matrix view with coverage
   */
  async getMatrix(platform?: string): Promise<MatrixView> {
    const params = platform ? `?platform=${platform}` : '';
    const response = await this.api.get(`/mitre/coverage/matrix${params}`);
    return response.data;
  }

  /**
   * Get techniques for a specific tactic
   */
  async getTechniquesForTactic(tacticId: string): Promise<MitreTechnique[]> {
    const response = await this.api.get(`/mitre/tactics/${tacticId}/techniques`);
    return response.data;
  }

  /**
   * Get rules that detect a specific technique
   */
  async getTechniqueRules(techniqueId: string): Promise<any[]> {
    const response = await this.api.get(`/mitre/techniques/${techniqueId}/rules`);
    return response.data;
  }

  /**
   * Get recent alerts for a specific technique
   */
  async getTechniqueAlerts(techniqueId: string, limit = 10): Promise<any[]> {
    const response = await this.api.get(`/mitre/techniques/${techniqueId}/alerts?limit=${limit}`);
    return response.data;
  }

  /**
   * Get analytics for a specific technique
   */
  async getTechniqueAnalytics(techniqueId: string): Promise<TechniqueAnalytics> {
    const response = await this.api.get(`/mitre/techniques/${techniqueId}/analytics`);
    return response.data;
  }

  /**
   * Get comprehensive coverage report
   */
  async getCoverageReport(): Promise<CoverageReport> {
    const response = await this.api.get('/mitre/coverage');
    return response.data;
  }

  /**
   * Get coverage matrix with detailed technique coverage
   */
  async getCoverageMatrix(): Promise<CoverageMatrix> {
    const response = await this.api.get('/mitre/coverage/matrix');
    return response.data;
  }

  /**
   * Search MITRE data (techniques, tactics, groups)
   */
  async search(query: string, limit = 20): Promise<{
    query: string;
    results: any[];
    total: number;
    result_type: string;
  }> {
    const response = await this.api.get(`/mitre/search?q=${encodeURIComponent(query)}&limit=${limit}`);
    return response.data;
  }

  /**
   * Get color for a tactic by name (client-side helper)
   */
  getTacticColor(tacticName: string): string {
    const colors: Record<string, string> = {
      'reconnaissance': '#8B4789',
      'resource-development': '#6B5B93',
      'initial-access': '#5F7A8B',
      'execution': '#4F8A8B',
      'persistence': '#458B74',
      'privilege-escalation': '#8B7355',
      'defense-evasion': '#8B5A3C',
      'credential-access': '#8B4726',
      'discovery': '#8B6914',
      'lateral-movement': '#6E8B3D',
      'collection': '#548B54',
      'command-and-control': '#2F8B87',
      'exfiltration': '#36648B',
      'impact': '#5D478B',
    };

    return colors[tacticName.toLowerCase()] || '#888888';
  }
}

export default MitreService;
