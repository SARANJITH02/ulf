export interface OcsfEndpoint {
  ip?: string;
  port?: number;
  hostname?: string;
  user?: string;
  isInternal?: boolean;
  mac?: string;
  zone?: string;
}

export interface OcsfEventDetail {
  category?: string;
  type?: string;
  action?: string;
  severity?: string;
  severityId?: number;
  message?: string;
}

export interface OcsfNetworkDetail {
  protocol?: string;
  direction?: string;
  transport?: string;
  bytesIn?: number;
  bytesOut?: number;
}

export interface OcsfObserverDetail {
  vendor?: string;
  product?: string;
  hostname?: string;
  version?: string;
}

export interface OcsfThreatDetail {
  riskScore?: number;
  mitreTechniqueId?: string;
  mitreTechniqueName?: string;
  mitreTactic?: string;
  category?: string;
}

export interface OcsfRawDetail {
  message?: string;
  format?: string;
}

export interface OcsfUlpfMetadata {
  schemaVersion?: string;
  parserName?: string;
  parserVersion?: string;
  mappingConfidence?: Record<string, number>;
  averageConfidence?: number;
  dlqStatus?: string;
  ecsAliases?: Record<string, string>;
}

export interface OcsfEvent {
  eventId: string;
  rawEventId: string;
  rawHashSha256: string;
  timestampUtc: string;
  event: OcsfEventDetail;
  source: OcsfEndpoint;
  destination: OcsfEndpoint;
  network: OcsfNetworkDetail;
  observer: OcsfObserverDetail;
  threat?: OcsfThreatDetail;
  raw: OcsfRawDetail;
  extensions?: Record<string, any>;
  ulpf: OcsfUlpfMetadata;
}

export interface NormalizedEventRecord {
  id: number;
  eventId: string;
  rawEventId: string;
  rawHashSha256: string;
  timestampUtc: string;
  category: string;
  eventType: string;
  action: string;
  severity: string;
  sourceIp: string;
  sourcePort?: number;
  destinationIp: string;
  destinationPort?: number;
  protocol: string;
  observerVendor: string;
  observerProduct: string;
  parserName: string;
  parserVersion: string;
  averageConfidence: number;
  format: string;
  ocsfJson: string;
  processedAt: string;
}

export interface FieldMappingItem {
  slotName: string;
  canonicalPath: string;
  inferredType: string;
  confidence: number;
  sampleValue: string;
  userOverridden?: boolean;
}

export interface InferenceResponse {
  rawSample: string;
  minedTemplate: string;
  synthesizedRegex: string;
  suggestedParserName: string;
  suggestedFormat: string;
  inferredMappings: FieldMappingItem[];
  confidenceMatrix: Record<string, number>;
  overallConfidence: number;
  confidenceTier: 'HIGH' | 'MEDIUM' | 'LOW';
  recommendedForApproval: boolean;
  previewNormalizedEvent: OcsfEvent;
  stage1Miner: string;
  stage2Recognizer: string;
}

export interface IntegrityCheckResponse {
  eventId: string;
  rawEventId: string;
  verified: boolean;
  storedRawHash: string;
  recomputedRawHash: string;
  normalizedStoredHash: string;
  rawByteLength: number;
  checkedAt: string;
  statusMessage: string;
  parserName: string;
  parserVersion: string;
  schemaVersion: string;
}

export interface MetricsSnapshot {
  timestamp: string;
  eventsPerSecond: number;
  totalEvents: number;
  successfulEvents: number;
  dlqEvents: number;
  successRatePercentage: number;
  avgLatencyMs: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  formatDistribution: Record<string, number>;
  confidenceDistribution: Record<string, number>;
}

export interface ParserSummary {
  name: string;
  displayName: string;
  version: string;
  formatType: string;
  parserType: string;
  active: boolean;
  confidence: number;
  templatePattern?: string;
}

export interface DlqRecord {
  id: number;
  rawEventId: string;
  rawMessage: string;
  failureCode: string;
  failureReason: string;
  detectedFormat: string;
  retryCount: number;
  status: string;
  createdAt: string;
  updatedAt: string;
}

export interface RuleItem {
  id: number;
  ruleKey: string;
  ruleName: string;
  ruleCategory: string;
  ruleValue: string;
  description: string;
  enabled: boolean;
  updatedAt: string;
  updatedBy: string;
}

// --- MERKLE AUDIT LEDGER ---
export interface MerkleProofNode {
  hash: string;
  direction: 'LEFT' | 'RIGHT';
}

export interface MerkleBatch {
  id: string;
  batchNumber: number;
  periodStart: string;
  periodEnd: string;
  eventCount: number;
  merkleRoot: string;
  leafOrderEventIds: string;
  createdAt: string;
}

export interface MerkleInclusionResult {
  eventId: string;
  rawEventId: string;
  rawHashSha256: string;
  merkleBatchId?: string;
  merkleRoot?: string;
  leafIndex?: number;
  totalLeaves?: number;
  proofPath?: MerkleProofNode[];
  verified: boolean;
  batchedAt?: string;
  verifiedAt: string;
  statusMessage: string;
}

// --- SIGMA DETECTION RULES ---
export interface SigmaRule {
  id: string;
  title: string;
  description?: string;
  sigmaYaml: string;
  logsourceCategory?: string;
  logsourceProduct?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  techniqueId?: string;
  tactic?: string;
  enabled: boolean;
  createdBy?: string;
  createdAt: string;
  updatedAt?: string;
}

export interface SigmaMatch {
  id: number;
  eventId: string;
  rawEventId?: string;
  ruleId: string;
  ruleTitle: string;
  severity: string;
  techniqueId?: string;
  tactic?: string;
  sourceIp?: string;
  destinationIp?: string;
  destinationPort?: number;
  details?: string;
  matchedAt: string;
}

// --- PARSER DRIFT MONITORING ---
export interface DriftAlert {
  id: number;
  parserName: string;
  parserVersion?: string;
  baselineConfidence: number;
  currentConfidence: number;
  confidenceDrop: number;
  successRate: number;
  totalEvents: number;
  dlqEvents: number;
  status: 'OPEN' | 'ACKNOWLEDGED';
  detectedAt: string;
  acknowledgedAt?: string;
  acknowledgedBy?: string;
  details?: string;
}

export interface ParserDriftMetrics {
  parserName: string;
  parserVersion: string;
  formatType: string;
  baselineConfidence: number;
  currentConfidence: number;
  confidenceDrop: number;
  successRate: number;
  sampleCount: number;
  dlqCount: number;
  healthStatus: 'HEALTHY' | 'WARNING' | 'DRIFT_ALERT';
  activeAlert: boolean;
  confidenceHistory: number[];
  lastChecked: string;
}

// --- UNIFIED WEBSOCKET ALERTS ---
export interface LiveAlertPayload {
  alertType: 'SIGMA_DETECTION' | 'PARSER_DRIFT' | 'CORRELATED_INCIDENT';
  type?: string;
  id: number;
  title?: string;
  ruleId?: string;
  parserName?: string;
  incidentKey?: string;
  correlationKey?: string;
  severity?: string;
  techniqueId?: string;
  tactic?: string;
  distinctTacticCount?: number;
  eventCount?: number;
  narrative?: string;
  details?: string;
  detectedAt?: string;
  matchedAt?: string;
}

// --- CORRELATED INCIDENTS ---
export interface CorrelatedIncident {
  id: number;
  incidentKey: string;
  correlationKey: string;
  keyType: 'IP' | 'USER';
  rootEventId: string;
  memberEventIds: string;
  tacticChain: string;
  narrativeText: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'OPEN' | 'INVESTIGATING' | 'CLOSED';
  distinctTacticCount: number;
  eventCount: number;
  firstSeenAt: string;
  lastSeenAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface IncidentMemberDetail {
  eventId: string;
  timestamp?: string;
  format?: string;
  sourceIp?: string;
  destinationIp?: string;
  destinationPort?: number;
  action?: string;
  severity?: string;
  matchedRules?: string[];
  techniqueId?: string;
  tactic?: string;
}

export interface IncidentDetailResponse {
  incident: CorrelatedIncident;
  memberEvents: IncidentMemberDetail[];
}


