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

export interface FileSystemFolderItem {
  folder_name: string;
  folder_path: string;
  parent_path: string;
  mft_entry_number: number | null;
  sequence_number: number | null;
  in_use: boolean;
  file_count: number;
  is_directory: boolean;
}

export interface FileSystemTreeResponse {
  case_id: string;
  parent_path: string;
  normalized_parent: string;
  folders: FileSystemFolderItem[];
  total_folders: number;
  source: string;
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

export interface ProcessCaseRequest {
  case_name: string;
  source_type: 'folder' | 'live_triage' | 'image' | 'directory';
  source_path?: string;
  target_dir?: string;
  enable_yara: boolean;
  enable_ocr: boolean;
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
  status: 'IDLE' | 'RUNNING' | 'COMPLETED' | 'SUCCESS' | 'FAILED' | 'UNKNOWN';
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
  category: string;
  artifact_name: string;
  primary_entity?: string;
  secondary_entity?: string;
  summary?: string;
  source_table: string;
  source_row_id: number;
  source_file?: string;
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

export interface CaseDashboardResponse {
  case_id: string;
  db_size_bytes: number;
  total_artifact_rows: number;
  timeline_total: number;
  connections_total: number;
  categories: CategoryBreakdown[];
  top_artifacts: TopArtifactItem[];
  top_users: TopConnectedEntity[];
  top_domains: TopConnectedEntity[];
  top_executables: TopConnectedEntity[];
  yara_hits: YaraHitSummary[];
  bookmarks: Bookmark[];
}

// ---------------------------------------------------------------------------
// HTTP Request Helper
// ---------------------------------------------------------------------------

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
      throw new Error(errorMsg);
    }

    return await res.json();
  } catch (err: unknown) {
    if (err instanceof Error) {
      console.error(`[API Error] ${endpoint}:`, err.message);
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
      tags?: string[] | string;
    }
  ): Promise<TableDataResponse> {
    const query = new URLSearchParams();
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.offset !== undefined) query.set('offset', String(params.offset));
    if (params?.search) query.set('search', params.search);
    if (params?.sort_col) query.set('sort_col', params.sort_col);
    if (params?.sort_dir) query.set('sort_dir', params.sort_dir.toUpperCase());
    if (params?.start_time) query.set('start_time', params.start_time);
    if (params?.end_time) query.set('end_time', params.end_time);
    if (params?.tags) {
      const tagsStr = Array.isArray(params.tags) ? JSON.stringify(params.tags) : params.tags;
      query.set('tags', tagsStr);
    }
    if (params?.column_filters) {
      const filtersStr =
        typeof params.column_filters === 'string'
          ? params.column_filters
          : JSON.stringify(params.column_filters);
      query.set('column_filters', filtersStr);
    }

    const qs = query.toString();
    const endpoint = `/api/cases/${encodeURIComponent(caseId)}/table/${encodeURIComponent(tableName)}${qs ? `?${qs}` : ''}`;
    return request<TableDataResponse>(endpoint);
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

  // Keyword Lists Management
  listKeywords(caseId: string): Promise<CaseKeywordsResponse> {
    return request<CaseKeywordsResponse>(`/api/cases/${encodeURIComponent(caseId)}/keywords`);
  },

  addKeywords(
    caseId: string,
    payload: { keywords: string[]; source_file?: string; is_regex?: boolean }
  ): Promise<CaseKeywordsResponse> {
    return request<CaseKeywordsResponse>(`/api/cases/${encodeURIComponent(caseId)}/keywords`, {
      method: 'POST',
      body: JSON.stringify({
        keywords: payload.keywords,
        source_file: payload.source_file || 'Manual',
        is_regex: Boolean(payload.is_regex),
      }),
    });
  },

  async uploadKeywordsFile(caseId: string, file: File): Promise<CaseKeywordsResponse> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/api/cases/${encodeURIComponent(caseId)}/keywords/upload`, {
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
    const formData = new FormData();
    formData.append('content', content);
    formData.append('source_name', sourceName);
    const res = await fetch(`${API_BASE}/api/cases/${encodeURIComponent(caseId)}/keywords/upload`, {
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
    return request<{ status: string; case_id: string; keyword_id: string }>(
      `/api/cases/${encodeURIComponent(caseId)}/keywords/${encodeURIComponent(keywordId)}`,
      {
        method: 'DELETE',
      }
    );
  },

  // Master Timeline
  getMasterTimeline(
    caseId: string,
    params?: {
      limit?: number;
      offset?: number;
      search?: string;
      category?: string;
      start_time?: string;
      end_time?: string;
    }
  ): Promise<TimelineResponse> {
    const query = new URLSearchParams();
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.offset !== undefined) query.set('offset', String(params.offset));
    if (params?.search) query.set('search', params.search);
    if (params?.category) query.set('category', params.category);
    if (params?.start_time) query.set('start_time', params.start_time);
    if (params?.end_time) query.set('end_time', params.end_time);

    const qs = query.toString();
    const endpoint = `/api/cases/${encodeURIComponent(caseId)}/timeline${qs ? `?${qs}` : ''}`;
    return request<TimelineResponse>(endpoint);
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

  // Hex & ASCII Viewer
  getHexViewer(
    caseId: string,
    filePath: string,
    offset = 0,
    length = 4096,
    signal?: AbortSignal
  ): Promise<HexViewerResponse> {
    const query = new URLSearchParams();
    query.set('file_path', filePath);
    query.set('offset', String(offset));
    query.set('length', String(length));

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
    signal?: AbortSignal
  ): Promise<HexViewerResponse> {
    return this.getHexViewer(caseId, filePath, offset, length, signal);
  },

  // Document & Media File Preview & Streaming
  getFileContent(caseId: string, filePath: string, maxBytes = 2000000, signal?: AbortSignal): Promise<FileContentResponse> {
    const query = new URLSearchParams();
    query.set('file_path', filePath);
    query.set('max_bytes', String(maxBytes));
    return request<FileContentResponse>(
      `/api/cases/${encodeURIComponent(caseId)}/file/content?${query.toString()}`,
      { signal }
    );
  },

  getFileRaw(caseId: string, filePath: string, signal?: AbortSignal): Promise<Blob> {
    const query = new URLSearchParams();
    query.set('file_path', filePath);
    const url = `${API_BASE}/api/cases/${encodeURIComponent(caseId)}/file/raw?${query.toString()}`;
    return fetch(url, { signal }).then((res) => {
      if (!res.ok) throw new Error(`HTTP Error ${res.status}: ${res.statusText}`);
      return res.blob();
    });
  },

  getFileRawUrl(caseId: string, filePath: string, download = false): string {
    const query = new URLSearchParams();
    query.set('file_path', filePath);
    if (download) query.set('download', 'true');
    return `${API_BASE}/api/cases/${encodeURIComponent(caseId)}/file/raw?${query.toString()}`;
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
    return `${API_BASE}/api/cases/${encodeURIComponent(caseId)}/export/file?file_path=${encodeURIComponent(filePath)}`;
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
      file_path?: string;
      is_folder?: boolean;
      table_name?: string;
      row_id?: number | string;
    }
  ): Promise<{
    success: boolean;
    cancelled?: boolean;
    destination_folder?: string;
    saved_path?: string;
    message?: string;
  }> {
    return request<{
      success: boolean;
      cancelled?: boolean;
      destination_folder?: string;
      saved_path?: string;
      message?: string;
    }>(`/api/cases/${encodeURIComponent(caseId)}/export/save-to-folder`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  // Places to Start Case Dashboard
  getCaseDashboard(caseId: string): Promise<CaseDashboardResponse> {
    return request<CaseDashboardResponse>(`/api/cases/${encodeURIComponent(caseId)}/dashboard`);
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
    params?: { hive?: string; category?: string; search?: string }
  ): Promise<RegRipperListResponse> {
    const query = new URLSearchParams();
    if (params?.hive) query.set('hive', params.hive);
    if (params?.category) query.set('category', params.category);
    if (params?.search) query.set('search', params.search);
    const qs = query.toString();
    return request<RegRipperListResponse>(
      `/api/cases/${encodeURIComponent(caseId)}/regripper/plugins${qs ? `?${qs}` : ''}`
    );
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
  getToolPaths(scan: boolean = false): Promise<ToolPathsMap> {
    return request<ToolPathsMap>(scan ? '/api/system/tool-paths?scan=true' : '/api/system/tool-paths');
  },

  scanTools(): Promise<{
    status: string;
    duration_ms: number;
    discovered_count: number;
    tools: ToolPathsMap;
  }> {
    return request('/api/system/scan-tools', {
      method: 'POST',
    });
  },

  saveToolPaths(paths: Record<string, string>): Promise<{ status: string; message: string; tools: ToolPathsMap; env_file_path?: string; saved_to_env?: boolean }> {
    return request<{ status: string; message: string; tools: ToolPathsMap; env_file_path?: string; saved_to_env?: boolean }>('/api/system/tool-paths', {
      method: 'POST',
      body: JSON.stringify({ paths }),
    });
  },

  runAutoSetupTools(): Promise<{
    status: string;
    exit_code: number;
    stdout: string;
    stderr: string;
    tools: ToolPathsMap;
    message: string;
  }> {
    return request('/api/system/auto-setup-tools', {
      method: 'POST',
    });
  },

  // File System Explorer (FTK Imager / WFT Style)
  getFilesystemTree(caseId: string, parentPath: string = ''): Promise<FileSystemTreeResponse> {
    const query = new URLSearchParams();
    if (parentPath) query.set('parent_path', parentPath);
    const qs = query.toString();
    return request<FileSystemTreeResponse>(
      `/api/cases/${encodeURIComponent(caseId)}/filesystem/tree${qs ? `?${qs}` : ''}`
    );
  },

  getFilesystemFiles(
    caseId: string,
    params?: {
      folder_path?: string;
      search?: string;
      limit?: number;
      offset?: number;
    }
  ): Promise<FileSystemFilesResponse> {
    const query = new URLSearchParams();
    if (params?.folder_path !== undefined) query.set('folder_path', params.folder_path);
    if (params?.search) query.set('search', params.search);
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.offset !== undefined) query.set('offset', String(params.offset));
    const qs = query.toString();
    return request<FileSystemFilesResponse>(
      `/api/cases/${encodeURIComponent(caseId)}/filesystem/files${qs ? `?${qs}` : ''}`
    );
  },

  // Event Logs Workbench & DFIR Hunting Profiles
  getEvtxProfiles(caseId: string): Promise<EvtxProfilesResponse> {
    return request<EvtxProfilesResponse>(`/api/cases/${encodeURIComponent(caseId)}/evtx/profiles`);
  },

  getEventProfiles(caseId?: string): Promise<EventProfilesListResponse> {
    const qs = caseId ? `?case_id=${encodeURIComponent(caseId)}` : '';
    return request<EventProfilesListResponse>(`/api/event-profiles${qs}`);
  },

  createEventProfile(profile: Partial<EventProfileItem>): Promise<{ status: string; message: string; profile: EventProfileItem }> {
    return request<{ status: string; message: string; profile: EventProfileItem }>('/api/event-profiles', {
      method: 'POST',
      body: JSON.stringify(profile),
    });
  },

  deleteEventProfile(profileId: string): Promise<{ status: string; message: string; total_profiles: number }> {
    return request<{ status: string; message: string; total_profiles: number }>(`/api/event-profiles/${encodeURIComponent(profileId)}`, {
      method: 'DELETE',
    });
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
    const qs = query.toString();
    return request<EvtxRowsResponse>(`/api/cases/${encodeURIComponent(caseId)}/evtx/rows${qs ? `?${qs}` : ''}`);
  },

  // Malware & Trellix Stinger Workbench
  getMalwareSummary(caseId: string): Promise<MalwareSummaryResponse> {
    return request<MalwareSummaryResponse>(`/api/cases/${encodeURIComponent(caseId)}/malware/summary`);
  },

  getMalwareRows(
    caseId: string,
    params?: {
      category?: string;
      search?: string;
      limit?: number;
      offset?: number;
      sort_col?: string;
      sort_dir?: string;
    }
  ): Promise<MalwareRowsResponse> {
    const query = new URLSearchParams();
    if (params?.category) query.set('category', params.category);
    if (params?.search) query.set('search', params.search);
    if (params?.limit !== undefined) query.set('limit', String(params.limit));
    if (params?.offset !== undefined) query.set('offset', String(params.offset));
    if (params?.sort_col) query.set('sort_col', params.sort_col);
    if (params?.sort_dir) query.set('sort_dir', params.sort_dir);
    const qs = query.toString();
    return request<MalwareRowsResponse>(`/api/cases/${encodeURIComponent(caseId)}/malware/rows${qs ? `?${qs}` : ''}`);
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
};
