import {
  OcsfEvent,
  NormalizedEventRecord,
  InferenceResponse,
  IntegrityCheckResponse,
  MetricsSnapshot,
  ParserSummary,
  DlqRecord,
  RuleItem,
  MerkleBatch,
  MerkleInclusionResult,
  SigmaRule,
  SigmaMatch,
  DriftAlert,
  ParserDriftMetrics,
  CorrelatedIncident,
  IncidentDetailResponse
} from './types';

const API_BASE = '/api/v1';

export class ApiClient {
  private static getToken(): string | null {
    return localStorage.getItem('ulpf-token');
  }

  private static async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const token = this.getToken();
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    let response: Response;
    try {
      response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers,
      });
    } catch (networkErr: any) {
      const msg = networkErr?.message || '';
      if (msg.includes('fetch') || msg.includes('NetworkError') || msg.includes('Failed to fetch')) {
        throw new Error('Unable to connect to ULPF backend. Ensure the backend server is running on port 8080.');
      }
      throw networkErr;
    }

    if (response.status === 401) {
      if (!endpoint.includes('/auth/login')) {
        this.logout();
        window.location.href = '/login';
        throw new Error('Authentication session expired. Redirecting to login...');
      }
    }

    if (response.status === 403) {
      // On general view/read endpoints, 403 indicates an expired/invalid token
      const isGeneralEndpoint =
        endpoint.startsWith('/dashboard') ||
        endpoint.startsWith('/incidents') ||
        endpoint.startsWith('/events') ||
        endpoint.startsWith('/audit') ||
        endpoint.startsWith('/rules/sigma') ||
        endpoint.startsWith('/parsers') ||
        !token;

      if (isGeneralEndpoint && !endpoint.includes('/auth/login')) {
        this.logout();
        window.location.href = '/login';
        throw new Error('Authentication session expired. Redirecting to login...');
      }

      throw new Error('Access denied: Administrator privileges required for this action.');
    }

    if (!response.ok) {
      let errorMessage = `HTTP Error ${response.status}`;
      try {
        const text = await response.text();
        if (text) {
          try {
            const errObj = JSON.parse(text);
            errorMessage = errObj.message || errObj.error || text;
          } catch {
            errorMessage = text;
          }
        }
      } catch {
        // fallback to HTTP status
      }
      throw new Error(errorMessage);
    }

    const text = await response.text();
    if (!text) {
      return {} as T;
    }
    try {
      return JSON.parse(text);
    } catch {
      return text as unknown as T;
    }
  }

  // Auth
  static async login(username: string, password: string): Promise<{ token: string; username: string; fullName: string; role: string }> {
    const data = await this.request<{ token: string; username: string; fullName: string; role: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    localStorage.setItem('ulpf-token', data.token);
    localStorage.setItem('ulpf-user', JSON.stringify({ username: data.username, fullName: data.fullName, role: data.role }));
    return data;
  }

  static logout() {
    localStorage.removeItem('ulpf-token');
    localStorage.removeItem('ulpf-user');
  }

  static getCurrentUser(): { username: string; fullName: string; role: string } | null {
    const u = localStorage.getItem('ulpf-user');
    return u ? JSON.parse(u) : null;
  }

  // Ingestion
  static async ingestSingle(log: string, source = 'UI_LAB'): Promise<any> {
    return this.request('/ingest', {
      method: 'POST',
      body: JSON.stringify({ message: log, source }),
    });
  }

  static async ingestBulk(logs: string[], source = 'UI_BULK'): Promise<any> {
    return this.request('/ingest', {
      method: 'POST',
      body: JSON.stringify({ logs, source }),
    });
  }

  // Inference (Unknown Log Lab)
  static async inferUnknownLog(logSample: string): Promise<InferenceResponse> {
    return this.request<InferenceResponse>('/infer', {
      method: 'POST',
      body: JSON.stringify({ logSample }),
    });
  }

  // Parsers & Operator Approval
  static async approveParser(payload: {
    parserName: string;
    displayName?: string;
    version?: string;
    formatType?: string;
    description?: string;
    templatePattern: string;
    regexPattern: string;
    fieldMappings: any[];
    averageConfidence?: number;
    sampleLog?: string;
  }): Promise<any> {
    return this.request('/parsers/approve', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  static async listParsers(): Promise<ParserSummary[]> {
    return this.request<ParserSummary[]>('/parsers');
  }

  static async toggleParser(name: string, active: boolean): Promise<any> {
    return this.request(`/parsers/${encodeURIComponent(name)}/toggle?active=${active}`, {
      method: 'POST',
    });
  }

  // Events & Integrity
  static async searchEvents(params: Record<string, string | number> = {}): Promise<{ content: NormalizedEventRecord[]; totalElements: number; totalPages: number }> {
    const query = new URLSearchParams(params as Record<string, string>).toString();
    return this.request(`/events?${query}`);
  }

  static async getRecentEvents(): Promise<NormalizedEventRecord[]> {
    return this.request<NormalizedEventRecord[]>('/events/recent');
  }

  static async getEvent(eventId: string): Promise<NormalizedEventRecord> {
    return this.request<NormalizedEventRecord>(`/events/${eventId}`);
  }

  static async getRawEvent(eventId: string): Promise<any> {
    return this.request(`/events/${eventId}/raw`);
  }

  static async verifyIntegrity(eventId: string): Promise<IntegrityCheckResponse> {
    return this.request<IntegrityCheckResponse>(`/events/${eventId}/verify`);
  }

  // DLQ
  static async listDlq(status?: string, page = 0, size = 25): Promise<{ content: DlqRecord[]; totalElements: number }> {
    const q = status ? `status=${status}&page=${page}&size=${size}` : `page=${page}&size=${size}`;
    return this.request(`/dlq?${q}`);
  }

  static async retryDlq(id: number): Promise<any> {
    return this.request(`/dlq/${id}/retry`, { method: 'POST' });
  }

  static async resolveDlq(id: number, status = 'RESOLVED'): Promise<any> {
    return this.request(`/dlq/${id}/resolve?status=${status}`, { method: 'POST' });
  }

  // Metrics
  static async getMetrics(): Promise<MetricsSnapshot> {
    return this.request<MetricsSnapshot>('/dashboard/metrics');
  }

  // Rules
  static async getRules(): Promise<RuleItem[]> {
    return this.request<RuleItem[]>('/rules');
  }

  static async updateRule(ruleKey: string, value: string, enabled?: boolean): Promise<RuleItem> {
    return this.request<RuleItem>(`/rules/${ruleKey}`, {
      method: 'PUT',
      body: JSON.stringify({ value, enabled }),
    });
  }

  // SIEM Export
  static async exportCef(eventId: string, event?: OcsfEvent): Promise<{ format: string; wireFormat: string }> {
    return this.request('/export/cef', {
      method: 'POST',
      body: JSON.stringify({ eventId, event }),
    });
  }

  static async exportLeef(eventId: string, event?: OcsfEvent): Promise<{ format: string; wireFormat: string }> {
    return this.request('/export/leef', {
      method: 'POST',
      body: JSON.stringify({ eventId, event }),
    });
  }

  static async exportEcs(eventId: string, event?: OcsfEvent): Promise<any> {
    return this.request('/export/ecs', {
      method: 'POST',
      body: JSON.stringify({ eventId, event }),
    });
  }

  static async exportBatch(eventIds: string[], targetFormat: string): Promise<any> {
    return this.request('/export/batch', {
      method: 'POST',
      body: JSON.stringify({ eventIds, targetFormat }),
    });
  }

  // Schema
  static async getSchema(): Promise<any> {
    return this.request('/schema');
  }

  // --- MERKLE AUDIT LEDGER ---
  static async listMerkleBatches(): Promise<MerkleBatch[]> {
    return this.request<MerkleBatch[]>('/audit/merkle-batches');
  }

  static async getMerkleBatch(id: string): Promise<MerkleBatch> {
    return this.request<MerkleBatch>(`/audit/merkle-batches/${encodeURIComponent(id)}`);
  }

  static async exportMerkleBatch(id: string): Promise<any> {
    return this.request<any>(`/audit/merkle-batches/${encodeURIComponent(id)}/export`);
  }

  static async triggerMerkleBatch(): Promise<MerkleBatch | { status: string; message: string }> {
    return this.request('/audit/merkle-batches/trigger', { method: 'POST' });
  }

  static async verifyMerkleInclusion(eventId: string): Promise<MerkleInclusionResult> {
    return this.request<MerkleInclusionResult>(`/events/${encodeURIComponent(eventId)}/verify-inclusion`);
  }

  // --- SIGMA DETECTION RULES ---
  static async listSigmaRules(): Promise<SigmaRule[]> {
    return this.request<SigmaRule[]>('/rules/sigma');
  }

  static async getSigmaRule(id: string): Promise<SigmaRule> {
    return this.request<SigmaRule>(`/rules/sigma/${encodeURIComponent(id)}`);
  }

  static async createSigmaRule(sigmaYaml: string): Promise<SigmaRule> {
    return this.request<SigmaRule>('/rules/sigma', {
      method: 'POST',
      body: JSON.stringify({ sigmaYaml }),
    });
  }

  static async updateSigmaRule(id: string, updates: { enabled?: boolean; sigmaYaml?: string }): Promise<SigmaRule> {
    return this.request<SigmaRule>(`/rules/sigma/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  }

  static async deleteSigmaRule(id: string): Promise<any> {
    return this.request(`/rules/sigma/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  static async listAlerts(params: Record<string, any> = {}): Promise<{ content: SigmaMatch[]; totalElements: number; totalPages: number }> {
    const query = new URLSearchParams(params as Record<string, string>).toString();
    return this.request(`/alerts?${query}`);
  }

  // --- PARSER DRIFT DETECTION ---
  static async getParserDrift(parserName: string): Promise<ParserDriftMetrics> {
    return this.request<ParserDriftMetrics>(`/parsers/${encodeURIComponent(parserName)}/drift`);
  }

  static async listDriftAlerts(status?: string): Promise<DriftAlert[]> {
    const q = status ? `?status=${status}` : '';
    return this.request<DriftAlert[]>(`/parsers/drift-alerts${q}`);
  }

  static async acknowledgeDriftAlert(id: number): Promise<DriftAlert> {
    return this.request<DriftAlert>(`/parsers/drift-alerts/${id}/acknowledge`, {
      method: 'PATCH',
    });
  }

  static async triggerDriftCheck(): Promise<{ status: string; newAlertsCount: number; alerts: DriftAlert[] }> {
    return this.request('/parsers/drift/check', { method: 'POST' });
  }

  // --- AUTO ROOT-CAUSE CORRELATED INCIDENTS ---
  static async listIncidents(status?: string): Promise<CorrelatedIncident[]> {
    const q = status ? `?status=${status}` : '';
    return this.request<CorrelatedIncident[]>(`/incidents${q}`);
  }

  static async getIncident(id: number): Promise<IncidentDetailResponse> {
    return this.request<IncidentDetailResponse>(`/incidents/${id}`);
  }

  static async updateIncidentStatus(id: number, status: string): Promise<CorrelatedIncident> {
    return this.request<CorrelatedIncident>(`/incidents/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
  }

  static async triggerCorrelation(windowMinutes = 30): Promise<{ status: string; incidentsCreatedOrUpdated: number; incidents: CorrelatedIncident[] }> {
    return this.request(`/incidents/correlate/trigger?windowMinutes=${windowMinutes}`, {
      method: 'POST',
    });
  }
}

