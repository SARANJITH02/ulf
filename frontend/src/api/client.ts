import {
  OcsfEvent,
  NormalizedEventRecord,
  InferenceResponse,
  IntegrityCheckResponse,
  MetricsSnapshot,
  ParserSummary,
  DlqRecord,
  RuleItem
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

    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });

    if (response.status === 401) {
      // Don't auto redirect on login failures
      if (!endpoint.includes('/auth/login')) {
        localStorage.removeItem('ulpf-token');
        localStorage.removeItem('ulpf-user');
        window.location.href = '/login';
      }
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || `HTTP Error ${response.status}`);
    }

    return response.json();
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
}
