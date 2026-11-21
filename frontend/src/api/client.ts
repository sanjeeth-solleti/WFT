/**
 * Windows Forensic Toolkit (WFT) - Typed REST Client
 * Connects to the FastAPI backend running on port 8765
 */

export const API_BASE = import.meta.env.VITE_API_URL !== undefined ? import.meta.env.VITE_API_URL : '';

// ---------------------------------------------------------------------------
// TypeScript Interfaces
// ---------------------------------------------------------------------------

export interface RegRipperPluginItem {
  _row_id: number;
  plugin_name: string;
  plugin_version: string;
  hive_name: string;
  hive_type: string;
  category: string;
  mitre_attack: string;
  description: string;
  summary_line: string;
  output_lines_count: number;
  parsed_at: string;
}

export interface RegRipperPluginDetail extends RegRipperPluginItem {
  report_text: string;
}

export interface RegRipperListResponse {
  case_id: string;
  total: number;
  plugins: RegRipperPluginItem[];
}

export interface CaseSummary {
  case_id: string;
  case_path: string;
  has_db: boolean;
  db_size_bytes: number;
  created_at: string;
  modified_at: string;
  total_artifact_rows: number;
  timeline_count: number;
  connections_count: number;
}

export interface ValidatePathResponse {
  valid: boolean;
  exists: boolean;
  path: string;
  clean_path?: string;
  raw_path?: string;
  is_file?: boolean;
  is_dir?: boolean;
  is_image?: boolean;
  is_archive?: boolean;
  size_bytes?: number;
  formatted_size?: string;
  detected_type?: string;
  contained_images?: string[];
  error?: string;
}

export interface BrowseDialogResponse {
  path: string;
  cancelled: boolean;
  exists?: boolean;
  error?: string;
}

export interface CarvedFileItem {
  carve_id: string;
  file_name?: string;
  file_type: string;
  extension: string;
  offset_bytes: number;
  size_bytes: number;
  sha256: string;
  carved_rel_path: string;
  source_region?: string;
  header_sig?: string;
  validated?: boolean;
}

export interface FileSystemFolderItem {
  folder_name: string;
  folder_path: string;
  parent_path: string;
  mft_entry_number: number | null;
  sequence_number: number | null;
  in_use: boolean;
  file_count: number;
  is_directory: boolean;
  // M5 real VFS / Partition / VSS / Carved extensions:
  name?: string;
  path?: string;
  is_dir?: boolean;
  is_deleted?: boolean;
  mft_entry?: number | null;
  node_type?: 'partition' | 'volume' | 'vss' | 'carved' | 'directory' | 'folder' | string;
  part_index?: number | null;
  vss_index?: number | null;
  label?: string | null;
  fs_type?: string | null;
  offset_bytes?: number | null;
  size_bytes?: number | null;
  size?: number | null;
  volume_serial?: string | null;
  is_boot?: boolean;
  store_id?: string | null;
  creation_time?: string | null;
  files_staged?: number | null;
  status?: string | null;
  children?: FileSystemFolderItem[];
}

export interface FileSystemTreeResponse {
  case_id?: string;
  parent_path?: string;
  normalized_parent?: string;
  folders: FileSystemFolderItem[];
  total_folders: number;
  source?: string;
  nodes?: FileSystemFolderItem[];
  items?: FileSystemFolderItem[];
  partitions?: DashboardPartitionInfo[];
  shadow_copies?: DashboardShadowCopyInfo[];
  carved_files?: CarvedFileItem[];
  carved_files_count?: number;
}

export interface FileSystemFileItem {
  file_name: string;
  full_path: string;
  extension: string | null;
  file_size: number;
  is_directory: boolean;
  in_use: boolean;
  mft_entry_number: number | null;
  sequence_number: number | null;
  si_created: string | null;
  si_modified: string | null;
  si_accessed: string | null;
  si_mft_modified: string | null;
  fn_created: string | null;
  fn_modified: string | null;
  staged_file_path?: string | null;
  // Full M5 $SI & $FN + Carved/VSS fields:
  name?: string;
  path?: string;
  size_bytes?: number;
  size?: number;
  is_dir?: boolean;
  is_deleted?: boolean;
  mft_entry?: number | null;
  si_changed?: string | null;
  fn_accessed?: string | null;
  fn_changed?: string | null;
  fn_mft_modified?: string | null;
  timestomped?: boolean;
  part_index?: number | null;
  vss_index?: number | null;
  sha256?: string | null;
  carve_id?: string | null;
  carved_rel_path?: string | null;
  source_region?: string | null;
  parent_path?: string | null;
}

export interface FileSystemFilesResponse {
  case_id: string;
  folder_path: string;
  normalized_folder: string;
  files: FileSystemFileItem[];
  total_files: number;
  limit: number;
  offset: number;
  source: string;
}

export interface DirectoryEntry {
  name: string;
  path: string;
  is_dir: boolean;
  is_drive?: boolean;
  size_bytes?: number;
  formatted_size?: string | null;
  is_image?: boolean;
  is_archive?: boolean;
  extension?: string;
  modified_at?: string | null;
}

export interface DriveInfo {
  name: string;
  path: string;
}

export interface QuickAccessItem {
  name: string;
  path: string;
  exists: boolean;
}

export interface ToolPathInfo {
  status: 'FOUND' | 'MISSING' | 'HEURISTICS READY';
  path: string | null;
  name: string;
  description: string;
  hint?: string;
  binary?: string;
  env_var?: string;
  configured_path?: string;
  resolved_path?: string | null;
  category?: 'main' | 'individual_ez' | string;
}

export type ToolPathsMap = Record<string, ToolPathInfo>;

export interface EvtxProfile {
  id: string;
  name: string;
  description: string;
  badge_color: string;
  hit_count: number;
  event_ids?: (number | string)[];
  channels?: string[];
  keywords?: string[];
  sql?: string;
  is_custom?: boolean;
}

export interface EventProfileItem {
  id: string;
  name: string;
  description: string;
  event_ids: (number | string)[];
  channels?: string[];
  keywords?: string[];
  badge_color?: string;
  sql?: string;
  hit_count?: number;
  is_custom?: boolean;
}

export interface EventProfilesListResponse {
  profiles: EventProfileItem[];
  total_profiles: number;
  profile_file_name: string;
  profile_file_path: string;
  raw_content: string;
}

export interface EvtxFileItem {
  source_file: string;
  file_name: string;
  display_name: string;
  channel: string;
  row_count: number;
}

export interface EvtxProfilesResponse {
  case_id: string;
  total_evtx_count: number;
  profiles: EvtxProfile[];
  files: EvtxFileItem[];
}

export interface EvtxRowsResponse {
  case_id: string;
  columns: string[];
  rows: Record<string, any>[];
  total_count: number;
  filtered_count: number;
  limit: number;
  offset: number;
}

export interface MalwareSummaryResponse {
  case_id: string;
  total_detections: number;
  stinger_hits: number;
  yara_matches: number;
  heuristics_count: number;
  stinger_installed: boolean;
  stinger_path: string | null;
  yara_rules_count: number;
  rule_files: string[];
}

export interface MalwareRowsResponse {
  case_id: string;
  columns: string[];
  rows: Record<string, any>[];
  total_count: number;
  filtered_count: number;
  limit: number;
  offset: number;
}

export interface ListDirectoryResponse {
  current_path: string;
  parent_path?: string | null;
  is_drive_root?: boolean;
  drives: DriveInfo[];
  quick_access: QuickAccessItem[];
  entries: DirectoryEntry[];
  total_entries: number;
  total_folders: number;
  total_images: number;
  error?: string | null;
}

export interface CasesListResponse {
  cases: CaseSummary[];
  total_cases: number;
}

export interface InitialKeywordSpec {
  keyword: string;
  is_regex?: boolean;
  case_sensitive?: boolean;
  category?: string;
  source_file?: string;
}

export interface ProcessCaseRequest {
  case_name: string;
  source_type: 'folder' | 'live_triage' | 'image' | 'directory';
  source_path?: string;
  target_dir?: string | null;
  case_number?: string;
  examiner?: string;
  notes?: string;
  enable_yara: boolean;
  enable_ioc?: boolean;
  enable_ocr: boolean;
  enable_stinger?: boolean;
  enable_hindsight?: boolean;
  enable_data_carving?: boolean;
  enable_carving?: boolean;
  enable_bulk_extractor?: boolean;
  enable_vss?: boolean;
  max_workers?: number;
  selected_artifacts?: string[];
  initial_keywords?: Array<InitialKeywordSpec | string>;
  keywords?: string[];
  case_id?: string;
  run_async?: boolean;
}

export interface ProcessCaseResponse {
  status: 'RUNNING' | 'SUCCESS' | 'ERROR';
  case_id: string;
  case_name: string;
  message: string;
  result?: Record<string, unknown>;
}

export interface ProcessingLog {
  log_id: number;
  timestamp_utc: string;
  module_name: string;
  command_executed: string;
  exit_code: number;
  rows_ingested: number;
  duration_ms: number;
  status: 'RUNNING' | 'SUCCESS' | 'WARNING' | 'ERROR';
  error_message?: string;
}

export interface CaseStatusResponse {
  case_id: string;
  status: 'IDLE' | 'RUNNING' | 'COMPLETED' | 'SUCCESS' | 'FAILED' | 'ERROR' | 'CANCELLED' | 'UNKNOWN';
  progress: number;
  current_step: string;
  error?: string;
  start_time?: string;
  end_time?: string;
  logs: ProcessingLog[];
  total_logs: number;
}

export interface ArtifactItem {
  artifact_id: string;
  category: string;
  display_name: string;
  table_name: string;
  source_tool: string;
  row_count: number;
  last_updated: string;
}

export interface ArtifactRegistryResponse {
  case_id: string;
  artifacts: ArtifactItem[];
  all_evidence_total?: number;
  total_artifact_categories: number;
  total_artifact_tables: number;
  timeline_total: number;
  connections_total: number;
}

export interface TableDataResponse {
  case_id: string;
  table_name: string;
  columns: string[];
  rows: Record<string, unknown>[];
  total_count: number;
  filtered_count: number;
  limit: number;
  offset: number;
}

export interface TimelineEvent {
  timeline_id: number;
  timestamp_utc: string;
  timestamp_type: string;
  macb?: string;
  category: string;
  artifact_name: string;
  primary_entity?: string;
  secondary_entity?: string;
  summary?: string;
  source_table: string;
  source_row_id: number;
  source_file?: string;
  is_deleted?: boolean;
  timestomped?: boolean;
  vss_index?: number | null;
  host?: string;
  user_account?: string;
}

export interface HistogramBucket {
  day: string;
  count: number;
}

export interface TimelineResponse {
  case_id: string;
  total_count: number;
  filtered_count: number;
  timeline: TimelineEvent[];
  histogram: HistogramBucket[];
  limit: number;
  offset: number;
  sort_dir?: string;
  min_timestamp_utc?: string | null;
  max_timestamp_utc?: string | null;
  around_timestamp?: string | null;
  window_minutes?: number | null;
}

export interface TimelineStatsResponse {
  case_id: string;
  total_events?: number;
  total_count?: number;
  min_timestamp_utc: string | null;
  max_timestamp_utc: string | null;
  categories?: Record<string, number>;
  macb_counts?: Record<string, number>;
}

export interface CytoscapeNodeData {
  id: string;
  label: string;
  type: 'PRIMARY_ENTITY' | 'ARTIFACT_NODE';
  entity_type?: string;
  category?: string;
  count?: number;
  occurrences?: number;
  artifact_count?: number;
}

export interface CytoscapeNode {
  data: CytoscapeNodeData;
}

export interface CytoscapeEdgeData {
  id: string;
  source: string;
  target: string;
  label?: string;
  count?: number;
}

export interface CytoscapeEdge {
  data: CytoscapeEdgeData;
}

export interface EntityOccurrence {
  connection_id: number;
  entity_type: string;
  entity_value: string;
  category: string;
  artifact_name: string;
  source_table: string;
  source_row_id: number;
  context_label?: string;
  timestamp_utc?: string;
}

export interface TopEntity {
  entity_type: string;
  entity_value: string;
  artifact_count: number;
  total_occurrences: number;
}

export interface ConnectionsResponse {
  case_id: string;
  entity_value?: string;
  entity_type?: string;
  nodes: CytoscapeNode[];
  edges: CytoscapeEdge[];
  occurrences: EntityOccurrence[];
  total_occurrences?: number;
  top_entities?: TopEntity[];
}

export interface HexLine {
  offset: number;
  offset_hex: string;
  hex_bytes: string;
  ascii_repr: string;
}

export interface HexViewerResponse {
  case_id: string;
  found?: boolean;
  error?: string;
  file_path: string;
  file_name: string;
  file_size: number;
  offset: number;
  length: number;
  lines: HexLine[];
}

export interface DistinctValueItem {
  value: unknown;
  count: number;
}

export interface FileContentResponse {
  case_id: string;
  found?: boolean;
  error?: string;
  file_name: string;
  file_path: string;
  file_size: number;
  extension: string;
  mime_type: string;
  is_text: boolean;
  is_image: boolean;
  is_pdf: boolean;
  is_media: boolean;
  is_office?: boolean;
  text_content?: string | null;
  truncated: boolean;
  raw_url: string;
}

export interface CaseKeyword {
  keyword_id: string;
  keyword: string;
  is_regex: boolean;
  case_sensitive?: boolean;
  category?: string;
  source_file?: string;
  hit_count: number;
  created_at: string;
}

export interface CaseKeywordsResponse {
  case_id: string;
  keywords: CaseKeyword[];
  total_keywords: number;
}

export interface Bookmark {
  bookmark_id: string;
  source_table: string;
  source_row_id: number;
  tag_name: string;
  examiner_notes?: string;
  created_at: string;
}

export interface BookmarkCreateRequest {
  source_table: string;
  source_row_id: number;
  tag_name: string;
  examiner_notes?: string;
  bookmark_id?: string;
}

export interface BookmarksListResponse {
  case_id: string;
  bookmarks: Bookmark[];
  total_bookmarks: number;
}

export interface CategoryBreakdown {
  category: string;
  count: number;
  percentage: number;
}

export interface TopArtifactItem {
  category: string;
  display_name: string;
  table_name: string;
  row_count: number;
}

export interface TopConnectedEntity {
  value: string;
  count: number;
}

export interface YaraHitSummary {
  rule_name: string;
  file_name: string;
  file_path: string;
  match_count: number;
  scanned_at: string;
}

export interface DashboardCaseMetadata {
  case_name?: string;
  case_number?: string;
  examiner?: string;
  notes?: string;
  source_path?: string;
  source_type?: string;
  image_size?: number | string | null;
  sha256?: string | null;
  max_workers?: number;
  enable_data_carving?: boolean;
  enable_bulk_extractor?: boolean;
  enable_vss?: boolean;
  created_utc?: string | null;
  [key: string]: any;
}

export interface DashboardOsInfo {
  hostname?: string | null;
  os_name?: string | null;
  os_edition?: string | null;
  edition?: string | null;
  os_build?: string | null;
  build?: string | null;
  install_date?: string | null;
  system_root?: string | null;
  timezone?: string | null;
  last_shutdown?: string | null;
  registered_owner?: string | null;
  domain_or_workgroup?: string | null;
  domain_workgroup?: string | null;
  users?: Array<string | { username?: string; value?: string; rid?: string | number; last_logon?: string; count?: number }>;
  [key: string]: any;
}

export interface DashboardPartitionInfo {
  part_index?: number;
  index?: number;
  slot?: string;
  label?: string;
  desc?: string;
  description?: string;
  fs_type?: string;
  offset_bytes?: number;
  start_offset?: number;
  start_sector?: number;
  size_bytes?: number;
  length?: number;
  volume_serial?: string | null;
  is_boot?: boolean;
  status?: string;
}

export interface DashboardShadowCopyInfo {
  vss_index?: number;
  vss_id?: string | number;
  part_index?: number;
  store_id?: string;
  shadow_id?: string;
  creation_time?: string | null;
  timestamp_utc?: string | null;
  volume?: string;
  size_bytes?: number;
  staged_prefix?: string;
  files_staged?: number;
  file_count?: number;
  status?: string;
}

export interface ToolExecutionSummaryItem {
  tool_name: string;
  stage?: string;
  status: string;
  row_count?: number;
  records_ingested?: number;
  duration_ms?: number;
  duration_sec?: number;
  message?: string | null;
}

export interface DashboardRefinedHighlights {
  domains?: Array<TopConnectedEntity | string>;
  users?: Array<TopConnectedEntity | string>;
  keyword_hits_count?: number;
  keyword_hits?: number;
  carved_files_count?: number;
  bulk_extractor_hits_count?: number;
  malware_hits_count?: number;
  malware_hits?: number;
  bookmarks_count?: number;
  [key: string]: any;
}

export interface CaseDashboardResponse {
  case_id: string;
  db_size_bytes: number;
  total_artifact_rows: number;
  total_artifacts?: number;
  timeline_total: number;
  timeline_events?: number;
  connections_total: number;
  min_timestamp_utc?: string | null;
  max_timestamp_utc?: string | null;
  category_counts?: Record<string, number>;
  categories: CategoryBreakdown[];
  top_artifacts: TopArtifactItem[];
  top_users: TopConnectedEntity[];
  top_domains: TopConnectedEntity[];
  top_executables: TopConnectedEntity[];
  top_hosts?: TopConnectedEntity[];
  top_ips?: TopConnectedEntity[];
  yara_hits: YaraHitSummary[];
  bookmarks: Bookmark[];
  provenance?: DashboardCaseMetadata;
  case_metadata?: DashboardCaseMetadata;
  os_info?: DashboardOsInfo;
  partitions?: DashboardPartitionInfo[];
  shadow_copies?: DashboardShadowCopyInfo[];
  tool_execution_summary?: ToolExecutionSummaryItem[];
  refined_highlights?: DashboardRefinedHighlights;
}

// ---------------------------------------------------------------------------
// HTTP Request & Filter Normalization Helpers
// ---------------------------------------------------------------------------

const CUSTOM_EVENT_PROFILES_STORAGE_KEY = 'wft_custom_event_profiles';

function readLocalCustomEventProfiles(): EventProfileItem[] {
  try {
    if (typeof window === 'undefined' || !window.localStorage) return [];
    const raw = window.localStorage.getItem(CUSTOM_EVENT_PROFILES_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeLocalCustomEventProfiles(items: EventProfileItem[]): void {
  try {
    if (typeof window === 'undefined' || !window.localStorage) return;
    window.localStorage.setItem(CUSTOM_EVENT_PROFILES_STORAGE_KEY, JSON.stringify(items));
  } catch {
    // ignore storage quota errors
  }
}

function appendGlobalFilterParams(
  query: URLSearchParams,
  params?: {
    start_time?: string;
    end_time?: string;
    date_from?: string;
    date_to?: string;
    keywords?: string[] | string;
    tags?: string[] | string;
    bookmarked_only?: boolean;
    content_types?: string[] | string;
  }
) {
  if (!params) return;
  const fromVal = (params.date_from || params.start_time || '').trim();
  const toVal = (params.date_to || params.end_time || '').trim();
  if (fromVal) {
    query.set('date_from', fromVal);
    query.set('start_time', fromVal);
  }
  if (toVal) {
    query.set('date_to', toVal);
    query.set('end_time', toVal);
  }
  if (params.keywords !== undefined) {
    if (Array.isArray(params.keywords)) {
      if (params.keywords.length > 0) query.set('keywords', JSON.stringify(params.keywords));
    } else if (params.keywords.trim()) {
      query.set('keywords', params.keywords.trim());
    }
  }
  if (params.tags !== undefined) {
    if (Array.isArray(params.tags)) {
      if (params.tags.length > 0) query.set('tags', JSON.stringify(params.tags));
    } else if (params.tags.trim()) {
      query.set('tags', params.tags.trim());
    }
  }
  if (params.bookmarked_only) {
    query.set('bookmarked_only', 'true');
  }
  if (params.content_types !== undefined) {
    if (Array.isArray(params.content_types) && params.content_types.length > 0) {
      query.set('content_types', JSON.stringify(params.content_types));
    } else if (typeof params.content_types === 'string' && params.content_types.trim()) {
      query.set('content_types', params.content_types.trim());
    }
  }
}

function normalizeToolPathsMap(raw: any): ToolPathsMap {
  if (!raw || typeof raw !== 'object') return {};
  const base: Record<string, ToolPathInfo> =
    'tools' in raw && raw.tools && typeof raw.tools === 'object' && !('status' in raw.tools)
      ? { ...(raw.tools as ToolPathsMap) }
      : { ...(raw as ToolPathsMap) };

  if (base['WFT_BULK_EXTRACTOR_EXE'] && !base['bulk_extractor']) {
    base['bulk_extractor'] = {
      ...base['WFT_BULK_EXTRACTOR_EXE'],
      env_var: base['WFT_BULK_EXTRACTOR_EXE'].env_var || 'WFT_BULK_EXTRACTOR_EXE',
      category: base['WFT_BULK_EXTRACTOR_EXE'].category || 'main',
    };
  }
  return base;
}

class ApiHttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options?.headers || {}),
      },
    });

    if (!res.ok) {
      let errorMsg = `HTTP Error ${res.status}: ${res.statusText}`;
      try {
        const errorData = await res.json();
        if (errorData?.detail) {
          errorMsg = typeof errorData.detail === 'string' ? errorData.detail : JSON.stringify(errorData.detail);
        }
      } catch {
        // use default error message
      }
      throw new ApiHttpError(res.status, errorMsg);
    }

    return await res.json();
  } catch (err: unknown) {
    if (err instanceof Error) {
      const isAborted =
        Boolean(options?.signal?.aborted) ||
        err.name === 'AbortError' ||
        /aborted/i.test(err.message);
      if (!isAborted) {
        console.error(`[API Error] ${endpoint}:`, err.message);
      }
      throw err;
    }
    throw new Error(String(err));
  }
}

// ---------------------------------------------------------------------------
// API Client Functions
// ---------------------------------------------------------------------------

export const apiClient = {
  // Case listing & management
  listCases(): Promise<CasesListResponse> {
    return request<CasesListResponse>('/api/cases');
  },

  deleteCase(caseId: string): Promise<{ status: string; message: string; deleted_case_id: string; deleted_paths?: string[] }> {
    return request<{ status: string; message: string; deleted_case_id: string; deleted_paths?: string[] }>(
      `/api/cases/${encodeURIComponent(caseId)}`,
      {
        method: 'DELETE',
      }
    );
  },

  processCase(params: ProcessCaseRequest): Promise<ProcessCaseResponse> {
    return request<ProcessCaseResponse>('/api/cases/process', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  },

  getCaseStatus(caseId: string): Promise<CaseStatusResponse> {
    return request<CaseStatusResponse>(`/api/cases/${encodeURIComponent(caseId)}/status`);
  },

  // Artifact Registry
  getArtifactRegistry(caseId: string, hideEmpty: boolean = false): Promise<ArtifactRegistryResponse> {
    const query = hideEmpty ? '?hide_empty=true' : '';
    return request<ArtifactRegistryResponse>(`/api/cases/${encodeURIComponent(caseId)}/registry${query}`);
  },

  // Table Data Grid
  getTableData(
    caseId: string,
    tableName: string,
    params?: {
      limit?: number;
      offset?: number;
      search?: string;
      sort_col?: string;
      sort_dir?: 'ASC' | 'DESC' | 'asc' | 'desc';
      column_filters?: Record<string, unknown[]> | string;
      start_time?: string;
      end_time?: string;
      date_from?: string;
      date_to?: string;
      keywords?: string[] | string;
      tags?: string[] | string;
      bookmarked_only?: boolean;
      content_types?: string[] | string;
    }
  ): Promise<TableDataResponse> {
    const query = new URLSearchParams();
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.offset !== undefined) query.set('offset', String(params.offset));
    if (params?.search) query.set('search', params.search);
    if (params?.sort_col) query.set('sort_col', params.sort_col);
    if (params?.sort_dir) query.set('sort_dir', params.sort_dir.toUpperCase());
    appendGlobalFilterParams(query, params);
    if (params?.column_filters) {
      const filtersStr =
        typeof params.column_filters === 'string'
          ? params.column_filters
          : JSON.stringify(params.column_filters);
      query.set('column_filters', filtersStr);
    }

    const qs = query.toString();
    const endpoint = `/api/cases/${encodeURIComponent(caseId)}/artifacts/${encodeURIComponent(tableName)}/query${qs ? `?${qs}` : ''}`;
    return request<TableDataResponse>(endpoint);
  },

  queryArtifacts(
    caseId: string,
    tableName: string,
    params?: {
      limit?: number;
      offset?: number;
      search?: string;
      sort_col?: string;
      sort_dir?: 'ASC' | 'DESC' | 'asc' | 'desc';
      column_filters?: Record<string, unknown[]> | string;
      start_time?: string;
      end_time?: string;
      date_from?: string;
      date_to?: string;
      keywords?: string[] | string;
      tags?: string[] | string;
      bookmarked_only?: boolean;
      content_types?: string[] | string;
    }
  ): Promise<TableDataResponse> {
    return this.getTableData(caseId, tableName, params);
  },

  // Distinct column values for multi-select filtering
  getDistinctColumnValues(
    caseId: string,
    tableName: string,
    columnName: string
  ): Promise<DistinctValueItem[]> {
    return request<DistinctValueItem[]>(
      `/api/cases/${encodeURIComponent(caseId)}/table/${encodeURIComponent(tableName)}/distinct/${encodeURIComponent(columnName)}`
    );
  },

  // Keyword Lists Management (NEVER fallback to 'pending_wizard_case')
  listKeywords(caseId: string): Promise<CaseKeywordsResponse> {
    const cleanId = (caseId || '').trim();
    if (!cleanId) {
      return Promise.resolve({ case_id: '', keywords: [], total_keywords: 0 });
    }
    return request<CaseKeywordsResponse>(`/api/cases/${encodeURIComponent(cleanId)}/keywords`);
  },

  addKeywords(
    caseId: string,
    payload: { keywords: string[]; source_file?: string; is_regex?: boolean; case_sensitive?: boolean; category?: string }
  ): Promise<CaseKeywordsResponse> {
    const cleanId = (caseId || '').trim();
    if (!cleanId) {
      return Promise.reject(new Error('Active case_id is required to add keywords via API.'));
    }
    return request<CaseKeywordsResponse>(`/api/cases/${encodeURIComponent(cleanId)}/keywords`, {
      method: 'POST',
      body: JSON.stringify({
        keywords: payload.keywords,
        source_file: payload.source_file || 'Manual',
        is_regex: Boolean(payload.is_regex),
        case_sensitive: Boolean(payload.case_sensitive),
        category: payload.category || 'General',
      }),
    });
  },

  async uploadKeywordsFile(caseId: string, file: File): Promise<CaseKeywordsResponse> {
    const cleanId = (caseId || '').trim();
    if (!cleanId) {
      throw new Error('Active case_id is required to upload keywords via API.');
    }
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/api/cases/${encodeURIComponent(cleanId)}/keywords/upload`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      let msg = `HTTP ${res.status}: ${res.statusText}`;
      try {
        const data = await res.json();
        if (data?.detail) msg = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
      } catch {
        // fallback
      }
      throw new Error(msg);
    }
    return await res.json();
  },

  async uploadKeywordsContent(caseId: string, content: string, sourceName = 'Manual Upload'): Promise<CaseKeywordsResponse> {
    const cleanId = (caseId || '').trim();
    if (!cleanId) {
      throw new Error('Active case_id is required to upload keywords via API.');
    }
    const formData = new FormData();
    formData.append('content', content);
    formData.append('source_name', sourceName);
    const res = await fetch(`${API_BASE}/api/cases/${encodeURIComponent(cleanId)}/keywords/upload`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      let msg = `HTTP ${res.status}: ${res.statusText}`;
      try {
        const data = await res.json();
        if (data?.detail) msg = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
      } catch {
        // fallback
      }
      throw new Error(msg);
    }
    return await res.json();
  },

  deleteKeyword(
    caseId: string,
    keywordId: string
  ): Promise<{ status: string; case_id: string; keyword_id: string }> {
    const cleanId = (caseId || '').trim();
    if (!cleanId) {
      return Promise.reject(new Error('Active case_id is required to delete keywords via API.'));
    }
    return request<{ status: string; case_id: string; keyword_id: string }>(
      `/api/cases/${encodeURIComponent(cleanId)}/keywords/${encodeURIComponent(keywordId)}`,
      {
        method: 'DELETE',
      }
    );
  },

  async scanKeywords(caseId: string): Promise<CaseKeywordsResponse> {
    const cleanId = (caseId || '').trim();
    if (!cleanId) {
      throw new Error('Active case_id is required to scan keywords.');
    }
    try {
      return await request<CaseKeywordsResponse>(`/api/cases/${encodeURIComponent(cleanId)}/keywords/scan`, {
        method: 'POST',
      });
    } catch (err: unknown) {
      if (err instanceof ApiHttpError && (err.status === 404 || err.status === 405)) {
        return await this.addKeywords(cleanId, { keywords: [] });
      }
      throw err;
    }
  },

  // Master Timeline
  getMasterTimeline(
    caseId: string,
    params?: {
      limit?: number;
      offset?: number;
      search?: string;
      category?: string;
      source?: string;
      sort_dir?: 'asc' | 'desc' | 'ASC' | 'DESC';
      macb?: string | string[];
      around_timestamp?: string;
      window_minutes?: number;
      start_time?: string;
      end_time?: string;
      date_from?: string;
      date_to?: string;
      keywords?: string[] | string;
      tags?: string[] | string;
      bookmarked_only?: boolean;
    }
  ): Promise<TimelineResponse> {
    const query = new URLSearchParams();
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.offset !== undefined) query.set('offset', String(params.offset));
    if (params?.search) query.set('search', params.search);
    if (params?.category) query.set('category', params.category);
    if (params?.source) {
      query.set('source', params.source);
      if (!params?.category) query.set('category', params.source);
    }
    if (params?.sort_dir) query.set('sort_dir', params.sort_dir.toLowerCase());
    if (params?.macb !== undefined) {
      const macbVal = Array.isArray(params.macb) ? params.macb.join(',') : params.macb;
      if (macbVal.trim()) query.set('macb', macbVal.trim());
    }
    if (params?.around_timestamp) query.set('around_timestamp', params.around_timestamp);
    if (params?.window_minutes !== undefined) query.set('window_minutes', String(params.window_minutes));
    appendGlobalFilterParams(query, params);

    const qs = query.toString();
    const endpoint = `/api/cases/${encodeURIComponent(caseId)}/timeline${qs ? `?${qs}` : ''}`;
    return request<TimelineResponse>(endpoint);
  },

  getTimeline(
    caseId: string,
    params?: {
      limit?: number;
      offset?: number;
      search?: string;
      category?: string;
      source?: string;
      sort_dir?: 'asc' | 'desc' | 'ASC' | 'DESC';
      macb?: string | string[];
      around_timestamp?: string;
      window_minutes?: number;
      start_time?: string;
      end_time?: string;
      date_from?: string;
      date_to?: string;
      keywords?: string[] | string;
      tags?: string[] | string;
      bookmarked_only?: boolean;
    }
  ): Promise<TimelineResponse> {
    return this.getMasterTimeline(caseId, params);
  },

  async getTimelineStats(caseId: string): Promise<TimelineStatsResponse> {
    try {
      return await request<TimelineStatsResponse>(`/api/cases/${encodeURIComponent(caseId)}/timeline/stats`);
    } catch {
      try {
        const dash = await this.getCaseDashboard(caseId);
        if (dash.max_timestamp_utc || dash.min_timestamp_utc) {
          return {
            case_id: caseId,
            total_events: dash.timeline_events ?? dash.timeline_total ?? 0,
            min_timestamp_utc: dash.min_timestamp_utc ?? null,
            max_timestamp_utc: dash.max_timestamp_utc ?? null,
          };
        }
      } catch {
        // fallback to latest timeline event below
      }
      try {
        const tl = await this.getMasterTimeline(caseId, { limit: 1 });
        return {
          case_id: caseId,
          total_events: tl.total_count ?? 0,
          min_timestamp_utc: tl.min_timestamp_utc ?? null,
          max_timestamp_utc: tl.max_timestamp_utc ?? tl.timeline?.[0]?.timestamp_utc ?? null,
        };
      } catch {
        return {
          case_id: caseId,
          total_events: 0,
          min_timestamp_utc: null,
          max_timestamp_utc: null,
        };
      }
    }
  },

  // Entity Connections Graph
  getEntityConnections(caseId: string, entityValue?: string): Promise<ConnectionsResponse> {
    const query = new URLSearchParams();
    if (entityValue !== undefined && entityValue.trim() !== '') {
      query.set('entity_value', entityValue.trim());
    }
    const qs = query.toString();
    const endpoint = `/api/cases/${encodeURIComponent(caseId)}/connections${qs ? `?${qs}` : ''}`;
    return request<ConnectionsResponse>(endpoint);
  },

  getConnections(caseId: string, entityValue?: string): Promise<ConnectionsResponse> {
    return this.getEntityConnections(caseId, entityValue);
  },

  // Hex & ASCII Viewer
  getHexViewer(
    caseId: string,
    filePath: string,
    offset = 0,
    length = 4096,
    signal?: AbortSignal,
    optional = false
  ): Promise<HexViewerResponse> {
    const query = new URLSearchParams();
    query.set('file_path', filePath);
    query.set('path', filePath);
    query.set('offset', String(offset));
    query.set('length', String(length));
    if (optional) query.set('optional', 'true');

    return request<HexViewerResponse>(
      `/api/cases/${encodeURIComponent(caseId)}/hex?${query.toString()}`,
      { signal }
    );
  },

  getHex(
    caseId: string,
    filePath: string,
    offset = 0,
    length = 4096,
    signal?: AbortSignal,
    optional = false
  ): Promise<HexViewerResponse> {
    return this.getHexViewer(caseId, filePath, offset, length, signal, optional);
  },

  // Document & Media File Preview & Streaming
  getFileContent(
    caseId: string,
    filePath: string,
    maxBytes = 2000000,
    signal?: AbortSignal,
    optional = false
  ): Promise<FileContentResponse> {
    const query = new URLSearchParams();
    query.set('file_path', filePath);
    query.set('path', filePath);
    query.set('max_bytes', String(maxBytes));
    if (optional) query.set('optional', 'true');
    return request<FileContentResponse>(
      `/api/cases/${encodeURIComponent(caseId)}/file/content?${query.toString()}`,
      { signal }
    );
  },

  getFileRaw(caseId: string, filePath: string, signal?: AbortSignal): Promise<Blob> {
    const query = new URLSearchParams();
    query.set('file_path', filePath);
    query.set('path', filePath);
    const url = `${API_BASE}/api/cases/${encodeURIComponent(caseId)}/file/raw?${query.toString()}`;
    return fetch(url, { signal }).then((res) => {
      if (!res.ok) throw new Error(`HTTP Error ${res.status}: ${res.statusText}`);
      return res.blob();
    });
  },

  getFileRawUrl(caseId: string, filePath: string, download = false): string {
    const query = new URLSearchParams();
    query.set('file_path', filePath);
    query.set('path', filePath);
    if (download) query.set('download', 'true');
    return `${API_BASE}/api/cases/${encodeURIComponent(caseId)}/file/raw?${query.toString()}`;
  },

  getPeAnalysis(caseId: string, filePath: string): Promise<Record<string, any>> {
    const query = new URLSearchParams();
    query.set('file_path', filePath);
    query.set('path', filePath);
    return request<Record<string, any>>(
      `/api/cases/${encodeURIComponent(caseId)}/vfs/pe-analysis?${query.toString()}`
    );
  },

  // Bookmarks
  createBookmark(caseId: string, payload: BookmarkCreateRequest): Promise<{ status: string; bookmark: Bookmark }> {
    return request<{ status: string; bookmark: Bookmark }>(
      `/api/cases/${encodeURIComponent(caseId)}/bookmarks`,
      {
        method: 'POST',
        body: JSON.stringify(payload),
      }
    );
  },

  listBookmarks(caseId: string): Promise<BookmarksListResponse> {
    return request<BookmarksListResponse>(`/api/cases/${encodeURIComponent(caseId)}/bookmarks`);
  },

  deleteBookmark(caseId: string, bookmarkId: string): Promise<{ status: string; bookmark_id: string }> {
    return request<{ status: string; bookmark_id: string }>(
      `/api/cases/${encodeURIComponent(caseId)}/bookmarks/${encodeURIComponent(bookmarkId)}`,
      {
        method: 'DELETE',
      }
    );
  },

  deleteBookmarkByRow(
    caseId: string,
    sourceTable: string,
    sourceRowId: number,
    tagName?: string
  ): Promise<{ status: string }> {
    const params = new URLSearchParams({
      source_table: sourceTable,
      source_row_id: String(sourceRowId),
    });
    if (tagName) params.append('tag_name', tagName);
    return request<{ status: string }>(
      `/api/cases/${encodeURIComponent(caseId)}/bookmarks?${params.toString()}`,
      { method: 'DELETE' }
    );
  },

  // File, Folder & Artifact Export Endpoints
  getExportFileUrl(caseId: string, filePath: string): string {
    return `${API_BASE}/api/cases/${encodeURIComponent(caseId)}/export/file?file_path=${encodeURIComponent(filePath)}&path=${encodeURIComponent(filePath)}`;
  },

  getExportFolderZipUrl(caseId: string, folderPath: string): string {
    return `${API_BASE}/api/cases/${encodeURIComponent(caseId)}/export/folder-zip?folder_path=${encodeURIComponent(folderPath)}`;
  },

  getTableExportCsvUrl(caseId: string, tableName: string, search?: string): string {
    const q = search ? `?search=${encodeURIComponent(search)}` : '';
    return `${API_BASE}/api/cases/${encodeURIComponent(caseId)}/table/${encodeURIComponent(tableName)}/export/csv${q}`;
  },

  saveToFolder(
    caseId: string,
    payload: {
      path?: string;
      file_path?: string;
      source_path?: string;
      destination_dir?: string;
      is_folder?: boolean;
      table_name?: string;
      row_id?: number | string;
    }
  ): Promise<{
    success: boolean;
    cancelled?: boolean;
    destination_folder?: string;
    destination_dir?: string;
    saved_path?: string;
    message?: string;
  }> {
    const effectivePath = payload.file_path ?? payload.path ?? payload.source_path;
    return request<{
      success: boolean;
      cancelled?: boolean;
      destination_folder?: string;
      destination_dir?: string;
      saved_path?: string;
      message?: string;
    }>(`/api/cases/${encodeURIComponent(caseId)}/export/save-to-folder`, {
      method: 'POST',
      body: JSON.stringify({
        ...payload,
        file_path: effectivePath,
        path: effectivePath,
      }),
    });
  },

  // Places to Start Case Dashboard & HTML Report
  getCaseDashboard(caseId: string): Promise<CaseDashboardResponse> {
    return request<CaseDashboardResponse>(`/api/cases/${encodeURIComponent(caseId)}/dashboard`);
  },

  getDashboard(caseId: string): Promise<CaseDashboardResponse> {
    return this.getCaseDashboard(caseId);
  },

  getHtmlReportUrl(caseId: string): string {
    return `${API_BASE}/api/cases/${encodeURIComponent(caseId)}/report/html`;
  },

  getCaseReportHtmlUrl(caseId: string): string {
    return this.getHtmlReportUrl(caseId);
  },

  async exportHtmlReport(caseId: string): Promise<string> {
    const url = this.getHtmlReportUrl(caseId);
    const res = await fetch(url, { headers: { Accept: 'text/html' } });
    if (!res.ok) {
      throw new Error(`HTTP Error ${res.status}: ${res.statusText}`);
    }
    return await res.text();
  },

  async exportCaseReportHtml(caseId: string): Promise<void> {
    const html = await this.exportHtmlReport(caseId);
    if (typeof window !== 'undefined' && typeof document !== 'undefined') {
      const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = `${caseId}_forensic_report.html`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(blobUrl), 2000);
    }
  },

  // System Native File / Folder Picker & Path Validation
  browse(targetType: 'file' | 'folder' = 'folder', initialDir?: string): Promise<{ selected_path: string; path?: string; cancelled?: boolean; exists?: boolean }> {
    const query = new URLSearchParams();
    query.set('target_type', targetType);
    if (initialDir) query.set('initial_dir', initialDir);
    return request<{ selected_path: string; path?: string; cancelled?: boolean; exists?: boolean }>(`/api/system/browse?${query.toString()}`);
  },

  browseFile(): Promise<BrowseDialogResponse> {
    return request<BrowseDialogResponse>('/api/system/browse-file');
  },

  browseFolder(): Promise<BrowseDialogResponse> {
    return request<BrowseDialogResponse>('/api/system/browse-folder');
  },

  validatePath(path: string): Promise<ValidatePathResponse> {
    return request<ValidatePathResponse>('/api/system/validate-path', {
      method: 'POST',
      body: JSON.stringify({ path }),
    });
  },

  listDirectory(path?: string): Promise<ListDirectoryResponse> {
    const query = new URLSearchParams();
    if (path) query.set('path', path);
    const qs = query.toString();
    return request<ListDirectoryResponse>(`/api/system/list-dir${qs ? `?${qs}` : ''}`);
  },

  // RegRipper 4.0 Endpoints
  getRegRipperPlugins(
    caseId: string,
    params?: {
      hive?: string;
      category?: string;
      search?: string;
      keywords?: string[] | string;
      date_from?: string;
      date_to?: string;
      start_time?: string;
      end_time?: string;
      tags?: string[] | string;
      bookmarked_only?: boolean;
    }
  ): Promise<RegRipperListResponse> {
    const query = new URLSearchParams();
    if (params?.hive) query.set('hive', params.hive);
    if (params?.category) query.set('category', params.category);
    if (params?.search) query.set('search', params.search);
    appendGlobalFilterParams(query, params);
    const qs = query.toString();
    return request<RegRipperListResponse>(
      `/api/cases/${encodeURIComponent(caseId)}/regripper/plugins${qs ? `?${qs}` : ''}`
    );
  },

  getRegRipperEntries(
    caseId: string,
    params?: {
      hive?: string;
      category?: string;
      search?: string;
      keywords?: string[] | string;
      date_from?: string;
      date_to?: string;
      start_time?: string;
      end_time?: string;
      tags?: string[] | string;
      bookmarked_only?: boolean;
    }
  ): Promise<RegRipperListResponse> {
    return this.getRegRipperPlugins(caseId, params);
  },

  getRegRipperPluginDetail(
    caseId: string,
    pluginName: string,
    hive?: string
  ): Promise<RegRipperPluginDetail> {
    const query = new URLSearchParams();
    if (hive) query.set('hive', hive);
    const qs = query.toString();
    return request<RegRipperPluginDetail>(
      `/api/cases/${encodeURIComponent(caseId)}/regripper/plugin/${encodeURIComponent(pluginName)}${qs ? `?${qs}` : ''}`
    );
  },

  runRegRipper(
    caseId: string
  ): Promise<{ status: string; plugins_parsed: number; duration_seconds: number }> {
    return request<{ status: string; plugins_parsed: number; duration_seconds: number }>(
      `/api/cases/${encodeURIComponent(caseId)}/regripper/run`,
      {
        method: 'POST',
      }
    );
  },

  // External Tool Paths
  async getToolPaths(scan: boolean = false): Promise<ToolPathsMap> {
    const raw = await request<any>(scan ? '/api/system/tool-paths?scan=true' : '/api/system/tool-paths');
    return normalizeToolPathsMap(raw);
  },

  async scanTools(): Promise<{
    status: string;
    duration_ms: number;
    discovered_count: number;
    tools: ToolPathsMap;
  }> {
    const res = await request<any>('/api/system/scan-tools', {
      method: 'POST',
    });
    return {
      ...res,
      tools: normalizeToolPathsMap(res?.tools ?? res),
    };
  },

  async saveToolPaths(paths: Record<string, string>): Promise<{ status: string; message: string; tools: ToolPathsMap; env_file_path?: string; saved_to_env?: boolean }> {
    const res = await request<any>('/api/system/tool-paths', {
      method: 'POST',
      body: JSON.stringify({ paths }),
    });
    return {
      ...res,
      tools: normalizeToolPathsMap(res?.tools ?? res),
    };
  },

  async runAutoSetupTools(): Promise<{
    status: string;
    exit_code: number;
    stdout: string;
    stderr: string;
    tools: ToolPathsMap;
    message: string;
  }> {
    try {
      const res = await request<any>('/api/system/auto-setup-tools', {
        method: 'POST',
      });
      return {
        ...res,
        tools: normalizeToolPathsMap(res?.tools ?? res),
      };
    } catch (err: unknown) {
      if (err instanceof ApiHttpError && err.status === 404) {
        const scanRes = await this.scanTools();
        return {
          status: scanRes.status || 'ok',
          exit_code: 0,
          stdout: `Scanned and synced ${scanRes.discovered_count ?? 0} forensic tools in ${scanRes.duration_ms ?? 0}ms.`,
          stderr: '',
          tools: normalizeToolPathsMap(scanRes.tools),
          message: 'Toolchain scan & sync completed.',
        };
      }
      throw err;
    }
  },

  // File System Explorer (FTK Imager / Magnet AXIOM Style)
  getFilesystemTree(caseId: string, parentPath: string = ''): Promise<FileSystemTreeResponse> {
    const query = new URLSearchParams();
    if (parentPath) {
      query.set('parent_path', parentPath);
      query.set('path', parentPath);
    }
    const qs = query.toString();
    return request<FileSystemTreeResponse>(
      `/api/cases/${encodeURIComponent(caseId)}/filesystem/tree${qs ? `?${qs}` : ''}`
    );
  },

  getVfsTree(caseId: string, path: string = ''): Promise<FileSystemTreeResponse> {
    return this.getFilesystemTree(caseId, path);
  },

  getFilesystemFiles(
    caseId: string,
    params?: {
      folder_path?: string;
      path?: string;
      part_index?: number;
      vss_index?: number;
      include_deleted?: boolean;
      carved_only?: boolean;
      sort_col?: string;
      sort_dir?: string;
      search?: string;
      keywords?: string[] | string;
      tags?: string[] | string;
      bookmarked_only?: boolean;
      date_from?: string;
      date_to?: string;
      start_time?: string;
      end_time?: string;
      content_types?: string[] | string;
      limit?: number;
      offset?: number;
    }
  ): Promise<FileSystemFilesResponse> {
    const query = new URLSearchParams();
    const effectiveFolder = params?.folder_path ?? params?.path;
    if (effectiveFolder !== undefined) {
      query.set('folder_path', effectiveFolder);
      query.set('path', effectiveFolder);
    }
    if (params?.part_index !== undefined) query.set('part_index', String(params.part_index));
    if (params?.vss_index !== undefined) query.set('vss_index', String(params.vss_index));
    if (params?.include_deleted !== undefined) query.set('include_deleted', String(params.include_deleted));
    if (params?.carved_only !== undefined) query.set('carved_only', String(params.carved_only));
    if (params?.sort_col) query.set('sort_col', params.sort_col);
    if (params?.sort_dir) query.set('sort_dir', params.sort_dir);
    if (params?.search) query.set('search', params.search);
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.offset !== undefined) query.set('offset', String(params.offset));
    appendGlobalFilterParams(query, params);
    const qs = query.toString();
    return request<FileSystemFilesResponse>(
      `/api/cases/${encodeURIComponent(caseId)}/filesystem/files${qs ? `?${qs}` : ''}`
    );
  },

  // Event Logs Workbench & DFIR Hunting Profiles
  async getEvtxProfiles(caseId: string): Promise<EvtxProfilesResponse> {
    const res = await request<EvtxProfilesResponse>(`/api/cases/${encodeURIComponent(caseId)}/evtx/profiles`);
    const localCustom = readLocalCustomEventProfiles();
    if (localCustom.length > 0) {
      const existingIds = new Set((res.profiles || []).map((p) => p.id));
      const extras: EvtxProfile[] = localCustom
        .filter((p) => !existingIds.has(p.id))
        .map((p) => ({
          id: p.id,
          name: p.name,
          description: p.description || '',
          badge_color: p.badge_color || 'blue',
          hit_count: p.hit_count ?? 0,
          event_ids: p.event_ids,
          channels: p.channels,
          keywords: p.keywords,
          sql: p.sql,
          is_custom: true,
        }));
      return {
        ...res,
        profiles: [...(res.profiles || []), ...extras],
      };
    }
    return res;
  },

  async getEventProfiles(caseId?: string): Promise<EventProfilesListResponse> {
    const qs = caseId ? `?case_id=${encodeURIComponent(caseId)}` : '';
    const res = await request<EventProfilesListResponse>(`/api/event-profiles${qs}`);
    const localCustom = readLocalCustomEventProfiles();
    if (localCustom.length > 0) {
      const existingIds = new Set((res.profiles || []).map((p) => p.id));
      const merged = [
        ...(res.profiles || []),
        ...localCustom.filter((p) => !existingIds.has(p.id)).map((p) => ({ ...p, is_custom: true })),
      ];
      return {
        ...res,
        profiles: merged,
        total_profiles: merged.length,
      };
    }
    return res;
  },

  async createEventProfile(profile: Partial<EventProfileItem>): Promise<{ status: string; message: string; profile: EventProfileItem }> {
    try {
      const res = await request<{ status: string; message: string; profile: EventProfileItem }>('/api/event-profiles', {
        method: 'POST',
        body: JSON.stringify(profile),
      });
      return res;
    } catch (err: unknown) {
      if (err instanceof ApiHttpError && (err.status === 404 || err.status === 405)) {
        const cleanId =
          (profile.id || '').trim() ||
          `custom_${(profile.name || 'profile').toLowerCase().replace(/[^a-z0-9]+/g, '_')}_${Date.now()}`;
        const item: EventProfileItem = {
          id: cleanId,
          name: (profile.name || cleanId).trim(),
          description: profile.description || 'Custom Forensic Event Profile',
          event_ids: profile.event_ids || [],
          channels: profile.channels || [],
          keywords: profile.keywords || [],
          badge_color: profile.badge_color || 'blue',
          sql: profile.sql,
          is_custom: true,
        };
        const current = readLocalCustomEventProfiles().filter((p) => p.id !== item.id);
        writeLocalCustomEventProfiles([...current, item]);
        return { status: 'ok', message: 'Saved custom event profile locally.', profile: item };
      }
      throw err;
    }
  },

  async deleteEventProfile(profileId: string): Promise<{ status: string; message: string; total_profiles: number }> {
    const currentLocal = readLocalCustomEventProfiles();
    const filteredLocal = currentLocal.filter((p) => p.id !== profileId);
    if (filteredLocal.length !== currentLocal.length) {
      writeLocalCustomEventProfiles(filteredLocal);
    }
    try {
      return await request<{ status: string; message: string; total_profiles: number }>(
        `/api/event-profiles/${encodeURIComponent(profileId)}`,
        {
          method: 'DELETE',
        }
      );
    } catch (err: unknown) {
      if (err instanceof ApiHttpError && (err.status === 404 || err.status === 405)) {
        return {
          status: 'ok',
          message: 'Deleted custom event profile.',
          total_profiles: filteredLocal.length,
        };
      }
      throw err;
    }
  },

  saveEventProfilesRaw(rawContent: string): Promise<{ status: string; message: string; total_profiles: number }> {
    return request<{ status: string; message: string; total_profiles: number }>('/api/event-profiles/raw', {
      method: 'PUT',
      body: JSON.stringify({ raw_content: rawContent }),
    });
  },

  getEvtxRows(
    caseId: string,
    params?: {
      profile_id?: string;
      file_name?: string;
      event_id?: number;
      level?: string;
      channel?: string;
      search?: string;
      keywords?: string[] | string;
      date_from?: string;
      date_to?: string;
      start_time?: string;
      end_time?: string;
      tags?: string[] | string;
      bookmarked_only?: boolean;
      limit?: number;
      offset?: number;
      sort_col?: string;
      sort_dir?: string;
    }
  ): Promise<EvtxRowsResponse> {
    const query = new URLSearchParams();
    if (params?.profile_id) query.set('profile_id', params.profile_id);
    if (params?.file_name) query.set('file_name', params.file_name);
    if (params?.event_id !== undefined && params?.event_id !== null) query.set('event_id', String(params.event_id));
    if (params?.level) query.set('level', params.level);
    if (params?.channel) query.set('channel', params.channel);
    if (params?.search) query.set('search', params.search);
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.offset !== undefined) query.set('offset', String(params.offset));
    if (params?.sort_col) query.set('sort_col', params.sort_col);
    if (params?.sort_dir) query.set('sort_dir', params.sort_dir);
    appendGlobalFilterParams(query, params);
    const qs = query.toString();
    return request<EvtxRowsResponse>(`/api/cases/${encodeURIComponent(caseId)}/evtx/rows${qs ? `?${qs}` : ''}`);
  },

  queryEventLogs(
    caseId: string,
    params?: {
      profile_id?: string;
      file_name?: string;
      event_id?: number;
      level?: string;
      channel?: string;
      search?: string;
      keywords?: string[] | string;
      date_from?: string;
      date_to?: string;
      start_time?: string;
      end_time?: string;
      tags?: string[] | string;
      bookmarked_only?: boolean;
      limit?: number;
      offset?: number;
      sort_col?: string;
      sort_dir?: string;
    }
  ): Promise<EvtxRowsResponse> {
    return this.getEvtxRows(caseId, params);
  },

  // Malware & Trellix Stinger Workbench
  getMalwareSummary(caseId: string): Promise<MalwareSummaryResponse> {
    return request<MalwareSummaryResponse>(`/api/cases/${encodeURIComponent(caseId)}/malware/summary`);
  },

  getMalwareRows(
    caseId: string,
    params?: {
      category?: string;
      severity?: string;
      search?: string;
      keywords?: string[] | string;
      date_from?: string;
      date_to?: string;
      start_time?: string;
      end_time?: string;
      tags?: string[] | string;
      bookmarked_only?: boolean;
      limit?: number;
      offset?: number;
      sort_col?: string;
      sort_dir?: string;
    }
  ): Promise<MalwareRowsResponse> {
    const query = new URLSearchParams();
    if (params?.category) query.set('category', params.category);
    if (params?.severity) query.set('severity', params.severity);
    if (params?.search) query.set('search', params.search);
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.offset !== undefined) query.set('offset', String(params.offset));
    if (params?.sort_col) query.set('sort_col', params.sort_col);
    if (params?.sort_dir) query.set('sort_dir', params.sort_dir);
    appendGlobalFilterParams(query, params);
    const qs = query.toString();
    return request<MalwareRowsResponse>(`/api/cases/${encodeURIComponent(caseId)}/malware/rows${qs ? `?${qs}` : ''}`);
  },

  getMalwareHits(
    caseId: string,
    params?: {
      category?: string;
      severity?: string;
      search?: string;
      keywords?: string[] | string;
      date_from?: string;
      date_to?: string;
      start_time?: string;
      end_time?: string;
      tags?: string[] | string;
      bookmarked_only?: boolean;
      limit?: number;
      offset?: number;
      sort_col?: string;
      sort_dir?: string;
    }
  ): Promise<MalwareRowsResponse> {
    return this.getMalwareRows(caseId, params);
  },

  scanMalware(
    caseId: string,
    options?: { enable_yara?: boolean; enable_stinger?: boolean; enable_ocr?: boolean }
  ): Promise<{ status: string; case_id: string; results: Record<string, number>; summary: MalwareSummaryResponse }> {
    return request<{ status: string; case_id: string; results: Record<string, number>; summary: MalwareSummaryResponse }>(
      `/api/cases/${encodeURIComponent(caseId)}/malware/scan`,
      {
        method: 'POST',
        body: JSON.stringify({
          enable_yara: options?.enable_yara ?? true,
          enable_stinger: options?.enable_stinger ?? true,
          enable_ocr: options?.enable_ocr ?? false,
        }),
      }
    );
  },

  async uploadYaraRule(caseId: string, file: File): Promise<{ status: string; message: string; path: string }> {
    const formData = new FormData();
    formData.append('file', file);
    const response = await fetch(`${API_BASE}/api/cases/${encodeURIComponent(caseId)}/malware/rules/upload`, {
      method: 'POST',
      body: formData,
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(err.detail || 'Failed to upload YARA rule');
    }
    return response.json();
  },

  getMediaStreamUrl(caseId: string, filePath: string): string {
    return `${API_BASE}/api/cases/${encodeURIComponent(caseId)}/raw-file?path=${encodeURIComponent(filePath)}`;
  },
};
