import React, { useEffect, useState, useCallback } from 'react';
import {
  apiClient,
  CaseDashboardResponse,
} from '../api/client';
import {
  LayoutDashboard,
  Layers,
  Clock,
  Network,
  HardDrive,
  ShieldAlert,
  Cpu,
  Globe,
  Terminal,
  ArrowRight,
  Bookmark as BookmarkIcon,
  ExternalLink,
  RefreshCw,
  User,
  FileDown,
  CheckCircle2,
  AlertTriangle,
  Database,
  Search,
} from 'lucide-react';

interface CaseDashboardProps {
  caseId: string;
  onExploreArtifact: (category: string, tableName?: string) => void;
  onGoToTimeline: () => void;
  onGoToEventLogs?: () => void;
  onGoToMalware?: () => void;
  onGoToFileSystem?: () => void;
  onGoToRegRipper?: () => void;
  onOpenKeywordManager?: () => void;
  onInspectEntity?: (entityValue: string) => void;
}

function formatBytesShort(bytes?: number | string | null): string {
  if (bytes === undefined || bytes === null || bytes === '') return '—';
  const n = typeof bytes === 'number' ? bytes : Number(bytes);
  if (!Number.isFinite(n) || n < 0) return String(bytes);
  if (n === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const idx = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  const val = n / Math.pow(1024, idx);
  return `${val >= 100 ? val.toFixed(0) : val.toFixed(1)} ${units[idx]}`;
}

export const CaseDashboard: React.FC<CaseDashboardProps> = ({
  caseId,
  onExploreArtifact,
  onGoToTimeline,
  onGoToEventLogs,
  onGoToMalware,
  onGoToFileSystem,
  onGoToRegRipper,
  onOpenKeywordManager,
  onInspectEntity,
}) => {
  const [dashboard, setDashboard] = useState<CaseDashboardResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isExportingHtml, setIsExportingHtml] = useState<boolean>(false);

  const fetchDashboard = useCallback(async () => {
    if (!caseId) {
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiClient.getCaseDashboard(caseId);
      setDashboard(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  const handleExportHtmlReport = async () => {
    if (!caseId || isExportingHtml) return;
    setIsExportingHtml(true);
    try {
      await apiClient.exportCaseReportHtml(caseId);
    } catch (err: unknown) {
      console.error('Failed to export HTML report:', err);
    } finally {
      setIsExportingHtml(false);
    }
  };

  if (!caseId) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center p-12 text-slate-500 gap-3 bg-[#f1f5f9] dark:bg-[#0f172a] font-sans h-full">
        <LayoutDashboard className="w-10 h-10 text-slate-400 mb-1" />
        <span className="font-bold text-[#0f172a] dark:text-[#f8fafc] text-sm">No Active Case Selected</span>
        <span className="text-xs text-slate-500 max-w-sm text-center">
          Please select or process evidence from the Process & Logs wizard to explore artifacts and analytics.
        </span>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center p-12 text-slate-500 gap-3 bg-[#f1f5f9] dark:bg-[#0f172a] h-full">
        <RefreshCw className="w-6 h-6 text-[#0284c7] dark:text-[#38bdf8] animate-spin" />
        <span className="font-mono text-xs tracking-wide">Loading Case Dashboard Overview...</span>
      </div>
    );
  }

  if (error || !dashboard) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center p-12 text-[#991b1b] dark:text-red-400 gap-3 bg-[#f1f5f9] dark:bg-[#0f172a] font-mono text-sm h-full">
        <span>Error loading case dashboard: {error || 'No case data'}</span>
        <button
          onClick={fetchDashboard}
          className="px-3 py-1.5 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc] text-xs rounded transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  const dbSizeMb = ((dashboard.db_size_bytes || 0) / (1024 * 1024)).toFixed(1);
  const osInfo = dashboard.os_info || {};
  const caseMeta = dashboard.case_metadata || dashboard.provenance || {};
  const partitions = dashboard.partitions || [];
  const shadowCopies = dashboard.shadow_copies || [];
  const toolSummary = dashboard.tool_execution_summary || [];
  const highlights = dashboard.refined_highlights || {};

  const localUsers: Array<{ label: string; meta?: string }> = (osInfo.users || []).map((u) => {
    if (typeof u === 'string') return { label: u };
    const label = u.username || u.value || '';
    const metaParts: string[] = [];
    if (u.rid !== undefined && u.rid !== null && u.rid !== '') metaParts.push(`RID ${u.rid}`);
    if (u.count !== undefined) metaParts.push(`${u.count}`);
    return { label, meta: metaParts.join(' · ') || undefined };
  }).filter((u) => Boolean(u.label));

  const refinedDomains: Array<{ value: string; count?: number }> = (
    highlights.domains && highlights.domains.length > 0 ? highlights.domains : dashboard.top_domains || []
  ).map((d) => (typeof d === 'string' ? { value: d } : { value: d.value, count: d.count }));

  const refinedUsers: Array<{ value: string; count?: number }> = (
    highlights.users && highlights.users.length > 0 ? highlights.users : dashboard.top_users || []
  ).map((u) => (typeof u === 'string' ? { value: u } : { value: u.value, count: u.count }));

  const keywordHitsCount = highlights.keyword_hits_count ?? highlights.keyword_hits ?? 0;
  const carvedFilesCount = highlights.carved_files_count ?? 0;
  const bulkExtractorCount = highlights.bulk_extractor_hits_count ?? 0;
  const malwareHitsCount =
    highlights.malware_hits_count ?? highlights.malware_hits ?? dashboard.yara_hits?.length ?? 0;
  const bookmarksCount = highlights.bookmarks_count ?? dashboard.bookmarks?.length ?? 0;

  return (
    <div className="flex-1 flex flex-col h-full bg-[#f1f5f9] dark:bg-[#0f172a] overflow-y-auto p-5 select-none font-sans text-[#0f172a] dark:text-[#f8fafc]">
      {/* 1. Header & Title Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-[#cbd5e1] dark:border-[#334155] shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded bg-[#0284c7] dark:bg-[#0369a1] border border-[#0369a1] dark:border-[#0284c7] flex items-center justify-center text-white">
            <LayoutDashboard className="w-5 h-5" />
          </div>
          <div className="flex flex-col">
            <h1 className="text-base font-bold text-[#0f172a] dark:text-[#f8fafc] flex items-center gap-2">
              <span>Places to Start</span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-white dark:bg-[#1e293b] text-[#0284c7] dark:text-[#38bdf8] border border-[#cbd5e1] dark:border-[#334155] font-normal">
                {caseId}
              </span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Magnet AXIOM-style case intelligence, operating system summary, partition/VSS topology, and artifact breakdown.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            data-testid="dashboard-export-html-btn"
            onClick={handleExportHtmlReport}
            disabled={isExportingHtml}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#0284c7] hover:bg-[#0369a1] text-white border border-[#0369a1] text-xs font-semibold rounded shadow-2xs transition-colors cursor-pointer disabled:opacity-60"
            title="Generate & Download Self-Contained Forensic HTML Case Report"
          >
            <FileDown className="w-3.5 h-3.5" />
            <span>{isExportingHtml ? 'Generating Report...' : 'Export HTML Case Report'}</span>
          </button>

          <button
            type="button"
            onClick={fetchDashboard}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc] text-xs rounded shadow-2xs transition-colors cursor-pointer"
            title="Refresh Dashboard"
          >
            <RefreshCw className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
            <span>Refresh Metrics</span>
          </button>
        </div>
      </div>

      {/* 2. Top Evidence Metric Cards (Solid Border Enterprise Design) */}
      <div className="grid grid-cols-1 content-start auto-rows-max items-start sm:grid-cols-2 lg:grid-cols-4 gap-3.5 mt-4">
        {/* Card 1: Artifact Rows */}
        <div className="p-3.5 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded shadow-2xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-600 dark:text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Total Evidence Rows</span>
            <Layers className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
          </div>
          <div
            data-testid="dashboard-total-artifact-rows"
            className="mt-2 text-2xl font-bold font-mono text-[#0f172a] dark:text-[#f8fafc]"
          >
            {dashboard.total_artifact_rows.toLocaleString()}
          </div>
          <span className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">Across all forensic artifact categories</span>
        </div>

        {/* Card 2: Timeline Events */}
        <div
          onClick={onGoToTimeline}
          className="p-3.5 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] hover:border-[#0284c7] dark:hover:border-[#38bdf8] rounded shadow-2xs flex flex-col justify-between cursor-pointer transition-colors group"
        >
          <div className="flex items-center justify-between text-slate-600 dark:text-slate-400 group-hover:text-[#0284c7] dark:group-hover:text-[#38bdf8]">
            <span className="text-xs font-semibold uppercase tracking-wider">Super-Timeline Events</span>
            <Clock className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-[#0f172a] dark:text-[#f8fafc] group-hover:text-[#0284c7] dark:group-hover:text-[#38bdf8]">
            {dashboard.timeline_total.toLocaleString()}
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400 group-hover:text-[#0284c7] dark:group-hover:text-[#38bdf8] mt-1">
            <span>Chronological unpivoted events</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </div>
        </div>

        {/* Card 3: Event Logs & Audit Records */}
        <div
          onClick={onGoToEventLogs}
          className="p-3.5 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] hover:border-amber-500 rounded shadow-2xs flex flex-col justify-between cursor-pointer transition-colors group"
        >
          <div className="flex items-center justify-between text-slate-600 dark:text-slate-400 group-hover:text-amber-500">
            <span className="text-xs font-semibold uppercase tracking-wider">Event Logs (EVTX)</span>
            <Cpu className="w-4 h-4 text-amber-500" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-[#0f172a] dark:text-[#f8fafc] group-hover:text-amber-500">
            {dashboard.categories.find(c => c.category === 'EVENT LOGS')?.count?.toLocaleString() || '0 (Not Parsed)'}
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400 group-hover:text-amber-500 mt-1">
            <span>Forensic Event Logs hunting workbench</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </div>
        </div>

        {/* Card 4: Database Storage */}
        <div className="p-3.5 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded shadow-2xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-600 dark:text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">DuckDB Database Size</span>
            <HardDrive className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-[#0f172a] dark:text-[#f8fafc]">
            {dbSizeMb} <span className="text-sm font-sans font-normal text-slate-500">MB</span>
          </div>
          <span className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">Zero-copy analytical columnar store</span>
        </div>
      </div>

      {/* 2B. Magnet AXIOM 4-Panel Case Intelligence Cards */}
      <div className="mt-5 grid grid-cols-1 lg:grid-cols-2 gap-4 content-start auto-rows-max items-start">
        {/* AXIOM Card 1: OS & System Information */}
        <div
          data-testid="dashboard-card-os-info"
          className="p-4 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded shadow-2xs flex flex-col gap-3"
        >
          <div className="flex items-center justify-between pb-2 border-b border-[#cbd5e1] dark:border-[#334155]">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-200">
              <Cpu className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
              <span>OS & System Information</span>
            </div>
            {onGoToRegRipper && (
              <button
                type="button"
                onClick={onGoToRegRipper}
                className="text-[11px] font-mono text-[#0284c7] dark:text-[#38bdf8] hover:underline flex items-center gap-1 cursor-pointer"
              >
                <span>Registry Hives</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            )}
          </div>

          <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
            <div>
              <span className="text-[10px] uppercase tracking-wider text-slate-400 block">Computer / Hostname</span>
              <span className="font-mono font-bold text-[#0f172a] dark:text-[#f8fafc] select-text">
                {osInfo.hostname || 'Not Detected'}
              </span>
            </div>
            <div>
              <span className="text-[10px] uppercase tracking-wider text-slate-400 block">Operating System</span>
              <span className="font-semibold text-[#0f172a] dark:text-[#f8fafc] select-text">
                {[osInfo.os_name, osInfo.os_edition || osInfo.edition].filter(Boolean).join(' ') || 'Windows (Unparsed Hive)'}
              </span>
            </div>
            <div>
              <span className="text-[10px] uppercase tracking-wider text-slate-400 block">OS Build</span>
              <span className="font-mono text-slate-700 dark:text-slate-300 select-text">
                {osInfo.os_build || osInfo.build || '—'}
              </span>
            </div>
            <div>
              <span className="text-[10px] uppercase tracking-wider text-slate-400 block">Install Date (UTC)</span>
              <span className="font-mono text-slate-700 dark:text-slate-300 select-text">
                {osInfo.install_date || '—'}
              </span>
            </div>
            <div>
              <span className="text-[10px] uppercase tracking-wider text-slate-400 block">System Root & Timezone</span>
              <span className="font-mono text-slate-700 dark:text-slate-300 select-text">
                {[osInfo.system_root, osInfo.timezone].filter(Boolean).join(' · ') || '—'}
              </span>
            </div>
            <div>
              <span className="text-[10px] uppercase tracking-wider text-slate-400 block">Last Shutdown (UTC)</span>
              <span className="font-mono text-slate-700 dark:text-slate-300 select-text">
                {osInfo.last_shutdown || '—'}
              </span>
            </div>
            <div>
              <span className="text-[10px] uppercase tracking-wider text-slate-400 block">Registered Owner</span>
              <span className="font-mono text-slate-700 dark:text-slate-300 select-text">
                {osInfo.registered_owner || '—'}
              </span>
            </div>
            <div>
              <span className="text-[10px] uppercase tracking-wider text-slate-400 block">Domain / Workgroup</span>
              <span className="font-mono text-slate-700 dark:text-slate-300 select-text">
                {osInfo.domain_or_workgroup || osInfo.domain_workgroup || '—'}
              </span>
            </div>
          </div>

          {/* Local User Accounts Pills */}
          <div className="pt-2 border-t border-[#e2e8f0] dark:border-[#334155]">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1.5">
              Local & Discovered User Accounts (Click to Pivot in Connections Graph)
            </span>
            {localUsers.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {localUsers.map((u, idx) => (
                  <button
                    key={`${u.label}-${idx}`}
                    type="button"
                    data-testid={`dashboard-local-user-${u.label}`}
                    onClick={() =>
                      onInspectEntity
                        ? onInspectEntity(u.label)
                        : onExploreArtifact('REFINED RESULTS', 'view_refined_users')
                    }
                    className="px-2 py-0.5 rounded bg-[#f8fafc] hover:bg-[#e0f2fe] dark:bg-[#0f172a] dark:hover:bg-[#0c4a6e] border border-[#cbd5e1] dark:border-[#334155] text-xs font-mono text-[#0284c7] dark:text-[#38bdf8] flex items-center gap-1.5 cursor-pointer transition-colors"
                    title={`Inspect "${u.label}" in Connections Graph`}
                  >
                    <User className="w-3 h-3 shrink-0" />
                    <span className="font-semibold">{u.label}</span>
                    {u.meta && <span className="text-[10px] text-slate-400">({u.meta})</span>}
                  </button>
                ))}
              </div>
            ) : dashboard.top_users && dashboard.top_users.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {dashboard.top_users.slice(0, 8).map((u, idx) => (
                  <button
                    key={`${u.value}-${idx}`}
                    type="button"
                    data-testid={`dashboard-local-user-${u.value}`}
                    onClick={() =>
                      onInspectEntity
                        ? onInspectEntity(u.value)
                        : onExploreArtifact('REFINED RESULTS', 'view_refined_users')
                    }
                    className="px-2 py-0.5 rounded bg-[#f8fafc] hover:bg-[#e0f2fe] dark:bg-[#0f172a] dark:hover:bg-[#0c4a6e] border border-[#cbd5e1] dark:border-[#334155] text-xs font-mono text-[#0284c7] dark:text-[#38bdf8] flex items-center gap-1.5 cursor-pointer transition-colors"
                    title={`Inspect "${u.value}" in Connections Graph`}
                  >
                    <User className="w-3 h-3 shrink-0" />
                    <span className="font-semibold">{u.value}</span>
                    <span className="text-[10px] text-slate-400">({u.count})</span>
                  </button>
                ))}
              </div>
            ) : (
              <span className="text-xs text-slate-400 italic">No user accounts extracted from SAM/Registry hives.</span>
            )}
          </div>

          {/* Optional Network Hosts / IPs */}
          {((dashboard.top_hosts && dashboard.top_hosts.length > 0) ||
            (dashboard.top_ips && dashboard.top_ips.length > 0)) && (
            <div className="pt-2 border-t border-[#e2e8f0] dark:border-[#334155] flex flex-wrap gap-1.5">
              {[...(dashboard.top_hosts || []).slice(0, 4), ...(dashboard.top_ips || []).slice(0, 4)].map(
                (item, idx) => (
                  <button
                    key={`${item.value}-${idx}`}
                    type="button"
                    onClick={() => onInspectEntity?.(item.value)}
                    className="px-2 py-0.5 rounded bg-slate-50 hover:bg-sky-50 dark:bg-[#0f172a] dark:hover:bg-[#0c4a6e] border border-[#cbd5e1] dark:border-[#334155] text-[11px] font-mono text-slate-700 dark:text-slate-300 flex items-center gap-1 cursor-pointer"
                  >
                    <Network className="w-3 h-3 text-[#0284c7] dark:text-[#38bdf8]" />
                    <span>{item.value}</span>
                  </button>
                )
              )}
            </div>
          )}
        </div>

        {/* AXIOM Card 2: Evidence Source, Partitions & Volume Shadow Copies */}
        <div
          data-testid="dashboard-card-partitions-vss"
          className="p-4 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded shadow-2xs flex flex-col gap-3"
        >
          <div className="flex items-center justify-between pb-2 border-b border-[#cbd5e1] dark:border-[#334155]">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-200">
              <HardDrive className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
              <span>Evidence Source, Partitions & Volume Shadow Copies</span>
            </div>
            {onGoToFileSystem && (
              <button
                type="button"
                onClick={onGoToFileSystem}
                className="text-[11px] font-mono text-[#0284c7] dark:text-[#38bdf8] hover:underline flex items-center gap-1 cursor-pointer"
              >
                <span>Open File System</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Provenance Metadata */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs bg-[#f8fafc] dark:bg-[#0f172a] p-2.5 rounded border border-[#e2e8f0] dark:border-[#334155]">
            <div>
              <span className="text-[10px] uppercase text-slate-400 block">Case / Number</span>
              <span className="font-mono font-semibold truncate block" title={caseMeta.case_name || caseId}>
                {caseMeta.case_name || caseId}
                {caseMeta.case_number ? ` (#${caseMeta.case_number})` : ''}
              </span>
            </div>
            <div>
              <span className="text-[10px] uppercase text-slate-400 block">Examiner & Threads</span>
              <span className="font-mono truncate block">
                {caseMeta.examiner || 'Examiner'}
                {caseMeta.max_workers ? ` · ${caseMeta.max_workers}w` : ''}
              </span>
            </div>
            <div>
              <span className="text-[10px] uppercase text-slate-400 block">Source Type & Size</span>
              <span className="font-mono truncate block">
                {caseMeta.source_type || 'evidence'} · {formatBytesShort(caseMeta.image_size)}
              </span>
            </div>
            {caseMeta.source_path && (
              <div className="col-span-2 sm:col-span-3">
                <span className="text-[10px] uppercase text-slate-400 block">Evidence Source Path</span>
                <span className="font-mono text-[11px] text-slate-600 dark:text-slate-300 break-all select-text">
                  {caseMeta.source_path}
                </span>
              </div>
            )}
          </div>

          {/* Partitions Table */}
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
              Detected Partitions ({partitions.length})
            </span>
            {partitions.length > 0 ? (
              <div className="overflow-x-auto border border-[#e2e8f0] dark:border-[#334155] rounded">
                <table className="w-full text-left text-[11px] font-mono border-collapse">
                  <thead className="bg-[#f8fafc] dark:bg-[#0f172a] text-[10px] uppercase text-slate-500 border-b border-[#e2e8f0] dark:border-[#334155]">
                    <tr>
                      <th className="py-1 px-2">#</th>
                      <th className="py-1 px-2">Label / Description</th>
                      <th className="py-1 px-2">FS</th>
                      <th className="py-1 px-2 text-right">Size</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#e2e8f0] dark:divide-[#334155]">
                    {partitions.map((part, idx) => (
                      <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-[#334155]/40">
                        <td className="py-1 px-2 font-bold text-[#0284c7] dark:text-[#38bdf8]">
                          P{part.part_index ?? part.index ?? idx}
                        </td>
                        <td className="py-1 px-2 truncate max-w-[180px]">
                          {part.label || part.description || part.desc || 'Volume'}
                        </td>
                        <td className="py-1 px-2">{part.fs_type || 'NTFS'}</td>
                        <td className="py-1 px-2 text-right">
                          {formatBytesShort(part.size_bytes ?? part.length)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <span className="text-xs text-slate-400 italic block">
                Logical folder / single-volume triage source (no multi-partition table).
              </span>
            )}
          </div>

          {/* Volume Shadow Copies Table */}
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
              Volume Shadow Copies ({shadowCopies.length})
            </span>
            {shadowCopies.length > 0 ? (
              <div className="overflow-x-auto border border-[#e2e8f0] dark:border-[#334155] rounded">
                <table className="w-full text-left text-[11px] font-mono border-collapse">
                  <thead className="bg-[#f8fafc] dark:bg-[#0f172a] text-[10px] uppercase text-slate-500 border-b border-[#e2e8f0] dark:border-[#334155]">
                    <tr>
                      <th className="py-1 px-2">VSS</th>
                      <th className="py-1 px-2">Creation Time (UTC)</th>
                      <th className="py-1 px-2 text-right">Staged</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#e2e8f0] dark:divide-[#334155]">
                    {shadowCopies.map((vss, idx) => (
                      <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-[#334155]/40">
                        <td className="py-1 px-2 font-bold text-purple-600 dark:text-purple-400">
                          VSS #{vss.vss_index ?? vss.vss_id ?? idx + 1}
                        </td>
                        <td className="py-1 px-2">{vss.creation_time || vss.timestamp_utc || '—'}</td>
                        <td className="py-1 px-2 text-right">
                          {(vss.files_staged ?? vss.file_count ?? 0).toLocaleString()} files
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <span className="text-xs text-slate-400 italic block">
                No Volume Shadow Copies enumerated or enabled for this run.
              </span>
            )}
          </div>
        </div>

        {/* AXIOM Card 3: Refined Identifiers & Recovery Summary */}
        <div
          data-testid="dashboard-card-refined-recovery"
          className="p-4 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded shadow-2xs flex flex-col gap-3"
        >
          <div className="flex items-center justify-between pb-2 border-b border-[#cbd5e1] dark:border-[#334155]">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-200">
              <Search className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
              <span>Refined Identifiers & Recovery Summary</span>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              {dashboard.connections_total?.toLocaleString() || 0} Graph Links
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
            <button
              type="button"
              onClick={() => onOpenKeywordManager?.()}
              className="p-2 rounded bg-[#f8fafc] hover:bg-sky-50 dark:bg-[#0f172a] dark:hover:bg-[#0c4a6e]/50 border border-[#e2e8f0] dark:border-[#334155] text-left cursor-pointer transition-colors"
            >
              <span className="text-[10px] uppercase text-slate-400 block">Keyword Hits</span>
              <span className="text-sm font-bold font-mono text-[#0284c7] dark:text-[#38bdf8]">
                {keywordHitsCount.toLocaleString()}
              </span>
            </button>

            <button
              type="button"
              onClick={() =>
                onGoToFileSystem ? onGoToFileSystem() : onExploreArtifact('FILE SYSTEM', 'carved_files')
              }
              className="p-2 rounded bg-[#f8fafc] hover:bg-amber-50 dark:bg-[#0f172a] dark:hover:bg-amber-950/30 border border-[#e2e8f0] dark:border-[#334155] text-left cursor-pointer transition-colors"
            >
              <span className="text-[10px] uppercase text-slate-400 block">Carved Files</span>
              <span className="text-sm font-bold font-mono text-amber-600 dark:text-amber-400">
                {carvedFilesCount.toLocaleString()}
              </span>
            </button>

            <button
              type="button"
              onClick={() => onExploreArtifact('REFINED RESULTS', 'parsed_bulk_extractor_features')}
              className="p-2 rounded bg-[#f8fafc] hover:bg-indigo-50 dark:bg-[#0f172a] dark:hover:bg-indigo-950/30 border border-[#e2e8f0] dark:border-[#334155] text-left cursor-pointer transition-colors"
            >
              <span className="text-[10px] uppercase text-slate-400 block">Bulk Extractor</span>
              <span className="text-sm font-bold font-mono text-indigo-600 dark:text-indigo-400">
                {bulkExtractorCount.toLocaleString()}
              </span>
            </button>

            <button
              type="button"
              onClick={() => (onGoToMalware ? onGoToMalware() : onExploreArtifact('MALWARE & YARA'))}
              className="p-2 rounded bg-[#f8fafc] hover:bg-rose-50 dark:bg-[#0f172a] dark:hover:bg-rose-950/30 border border-[#e2e8f0] dark:border-[#334155] text-left cursor-pointer transition-colors"
            >
              <span className="text-[10px] uppercase text-slate-400 block">Malware Hits</span>
              <span className="text-sm font-bold font-mono text-rose-600 dark:text-rose-400">
                {malwareHitsCount.toLocaleString()}
              </span>
            </button>

            <div className="p-2 rounded bg-[#f8fafc] dark:bg-[#0f172a] border border-[#e2e8f0] dark:border-[#334155] text-left">
              <span className="text-[10px] uppercase text-slate-400 block">Bookmarks</span>
              <span className="text-sm font-bold font-mono text-emerald-600 dark:text-emerald-400">
                {bookmarksCount.toLocaleString()}
              </span>
            </div>
          </div>

          <div className="space-y-2">
            <div>
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                Highlighted Domains & Endpoints
              </span>
              {refinedDomains.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {refinedDomains.slice(0, 6).map((d, i) => (
                    <button
                      key={`${d.value}-${i}`}
                      type="button"
                      onClick={() =>
                        onInspectEntity
                          ? onInspectEntity(d.value)
                          : onExploreArtifact('REFINED RESULTS', 'view_refined_domains')
                      }
                      className="px-2 py-0.5 rounded bg-[#f8fafc] hover:bg-[#e0f2fe] dark:bg-[#0f172a] dark:hover:bg-[#0c4a6e] border border-[#cbd5e1] dark:border-[#334155] text-[11px] font-mono text-[#0284c7] dark:text-[#38bdf8] cursor-pointer"
                    >
                      {d.value}
                      {d.count !== undefined ? ` (${d.count})` : ''}
                    </button>
                  ))}
                </div>
              ) : (
                <span className="text-xs text-slate-400 italic">No refined domains indexed yet.</span>
              )}
            </div>

            {refinedUsers.length > 0 && (
              <div>
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                  Highlighted Identity Principals
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {refinedUsers.slice(0, 6).map((u, i) => (
                    <button
                      key={`${u.value}-${i}`}
                      type="button"
                      onClick={() =>
                        onInspectEntity
                          ? onInspectEntity(u.value)
                          : onExploreArtifact('REFINED RESULTS', 'view_refined_users')
                      }
                      className="px-2 py-0.5 rounded bg-[#f8fafc] hover:bg-[#e0f2fe] dark:bg-[#0f172a] dark:hover:bg-[#0c4a6e] border border-[#cbd5e1] dark:border-[#334155] text-[11px] font-mono text-slate-700 dark:text-slate-200 cursor-pointer"
                    >
                      {u.value}
                      {u.count !== undefined ? ` (${u.count})` : ''}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* AXIOM Card 4: External Tool & Parser Execution Health */}
        <div
          data-testid="dashboard-card-tool-health"
          className="p-4 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded shadow-2xs flex flex-col gap-3"
        >
          <div className="flex items-center justify-between pb-2 border-b border-[#cbd5e1] dark:border-[#334155]">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-200">
              <Database className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
              <span>External Tool & Parser Execution Health</span>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              {toolSummary.length} modules logged
            </span>
          </div>

          {toolSummary.length > 0 ? (
            <div className="overflow-x-auto max-h-56 overflow-y-auto border border-[#e2e8f0] dark:border-[#334155] rounded">
              <table className="w-full text-left text-[11px] font-mono border-collapse">
                <thead className="sticky top-0 bg-[#f8fafc] dark:bg-[#0f172a] text-[10px] uppercase text-slate-500 border-b border-[#e2e8f0] dark:border-[#334155]">
                  <tr>
                    <th className="py-1.5 px-2">Tool / Parser</th>
                    <th className="py-1.5 px-2">Status</th>
                    <th className="py-1.5 px-2 text-right">Rows</th>
                    <th className="py-1.5 px-2 text-right">Duration</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#e2e8f0] dark:divide-[#334155]">
                  {toolSummary.map((item, idx) => {
                    const st = String(item.status || 'SUCCESS').toUpperCase();
                    const isOk = st.includes('SUCCESS') || st.includes('OK') || st.includes('COMPLET');
                    const isErr = st.includes('ERR') || st.includes('FAIL');
                    const rowsCount = item.row_count ?? item.records_ingested ?? 0;
                    const durText =
                      item.duration_ms !== undefined
                        ? `${(item.duration_ms / 1000).toFixed(2)}s`
                        : item.duration_sec !== undefined
                        ? `${Number(item.duration_sec).toFixed(2)}s`
                        : '—';

                    return (
                      <tr key={`${item.tool_name}-${idx}`} className="hover:bg-slate-50 dark:hover:bg-[#334155]/40">
                        <td className="py-1 px-2 font-semibold truncate max-w-[180px]" title={item.message || item.tool_name}>
                          {item.tool_name}
                        </td>
                        <td className="py-1 px-2">
                          <span
                            className={`inline-flex items-center gap-1 px-1.5 py-0.2 rounded text-[10px] font-bold ${
                              isOk
                                ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300'
                                : isErr
                                ? 'bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300'
                                : 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300'
                            }`}
                          >
                            {isOk ? (
                              <CheckCircle2 className="w-2.5 h-2.5" />
                            ) : (
                              <AlertTriangle className="w-2.5 h-2.5" />
                            )}
                            <span>{st}</span>
                          </span>
                        </td>
                        <td className="py-1 px-2 text-right">{rowsCount.toLocaleString()}</td>
                        <td className="py-1 px-2 text-right text-slate-500">{durText}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-4 text-center text-xs text-slate-400 italic bg-[#f8fafc] dark:bg-[#0f172a] rounded border border-[#e2e8f0] dark:border-[#334155]">
              No external tool execution audit records logged for this case yet.
            </div>
          )}
        </div>
      </div>

      {/* 3. YARA Malware Alert Banner (Strict Contrast Flat Red) */}
      {dashboard.yara_hits && dashboard.yara_hits.length > 0 && (
        <div className="mt-4 p-3 bg-red-50 dark:bg-red-950/40 border border-red-300 dark:border-red-900 rounded shadow-2xs flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-[#991b1b] dark:text-red-300 font-bold text-xs uppercase tracking-wider">
              <ShieldAlert className="w-4 h-4 text-[#991b1b] dark:text-red-400" />
              <span>YARA-X Malware Rule Hits Detected ({dashboard.yara_hits.length} Rule Hits)</span>
            </div>
            <button
              onClick={() => onExploreArtifact('Malware & Threat Hunting', 'artifact_yara_hits')}
              className="text-xs font-mono text-[#991b1b] dark:text-red-300 hover:underline flex items-center gap-1 cursor-pointer font-bold"
            >
              <span>View Rule Hits Table</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
          <div className="flex flex-wrap gap-2 pt-1">
            {dashboard.yara_hits.map((hit, idx) => (
              <span
                key={idx}
                className="px-2 py-0.5 rounded bg-white dark:bg-red-900/60 border border-red-300 dark:border-red-700 text-[#991b1b] dark:text-red-200 text-xs font-mono flex items-center gap-1.5"
                title={`${hit.file_name} (${hit.file_path})`}
              >
                <span className="font-bold">{hit.rule_name}</span>
                <span className="text-slate-600 dark:text-red-300">in {hit.file_name}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* 4. Category Breakdown Grid (WFT "Places to Start" Cards) */}
      <div className="mt-5">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
            <span>Official Evidence Category Breakdown</span>
          </h2>
          <span className="text-xs text-slate-500">
            Click any category card to examine related evidentiary records
          </span>
        </div>

        <div className="grid grid-cols-1 content-start auto-rows-max items-start md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
          {dashboard.categories.map((catItem) => (
            <div
              key={catItem.category}
              onClick={() => onExploreArtifact(catItem.category)}
              className="p-3 bg-white dark:bg-[#1e293b] hover:bg-slate-50 dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] hover:border-[#0284c7] dark:hover:border-[#38bdf8] rounded shadow-2xs cursor-pointer transition-colors flex flex-col justify-between group"
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-2 overflow-hidden pr-1">
                  <Layers className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />
                  <span className="font-bold text-xs text-[#0f172a] dark:text-[#f8fafc] group-hover:text-[#0284c7] dark:group-hover:text-[#38bdf8] truncate">
                    {catItem.category}
                  </span>
                </div>
                <ArrowRight className="w-3 h-3 text-slate-400 group-hover:text-[#0284c7] dark:group-hover:text-[#38bdf8] shrink-0 transition-transform group-hover:translate-x-0.5" />
              </div>

              <div className="mt-3 flex items-baseline justify-between">
                <span className="text-lg font-bold font-mono text-[#0f172a] dark:text-[#f8fafc] group-hover:text-[#0284c7] dark:group-hover:text-[#38bdf8]">
                  {catItem.count.toLocaleString()}
                </span>
                <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                  {catItem.percentage}%
                </span>
              </div>

              {/* Progress / Percentage Bar (Solid WFT Blue) */}
              <div className="w-full bg-[#f1f5f9] dark:bg-[#0f172a] rounded h-1.5 mt-2 overflow-hidden border border-[#cbd5e1] dark:border-[#334155]">
                <div
                  className="bg-[#0284c7] dark:bg-[#38bdf8] h-1.5 rounded"
                  style={{ width: `${Math.min(100, Math.max(5, catItem.percentage))}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 5. Top Connected Entities Section (3 Column Enterprise Tables) */}
      <div className="mt-6 grid grid-cols-1 content-start auto-rows-max items-start md:grid-cols-3 gap-4">
        {/* Column 1: Top Users & Identifiers */}
        <div className="p-3.5 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded shadow-2xs flex flex-col">
          <div className="flex items-center justify-between pb-2 border-b border-[#cbd5e1] dark:border-[#334155] text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
            <div className="flex items-center gap-1.5">
              <User className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
              <span>Top User Accounts</span>
            </div>
            <button
              onClick={() => onExploreArtifact('REFINED RESULTS', 'view_refined_users')}
              className="text-[11px] text-[#0284c7] dark:text-[#38bdf8] hover:underline flex items-center gap-0.5 font-mono cursor-pointer"
            >
              <span>View All</span>
              <ExternalLink className="w-2.5 h-2.5" />
            </button>
          </div>
          <div className="mt-2.5 space-y-1">
            {dashboard.top_users && dashboard.top_users.length > 0 ? (
              dashboard.top_users.map((u, i) => (
                <button
                  key={i}
                  onClick={() =>
                    onInspectEntity
                      ? onInspectEntity(u.value)
                      : onExploreArtifact('REFINED RESULTS', 'view_refined_users')
                  }
                  className="w-full flex items-center justify-between p-1.5 rounded hover:bg-[#f1f5f9] dark:hover:bg-[#334155] text-left transition-colors group cursor-pointer"
                >
                  <span className="text-xs font-mono text-[#0f172a] dark:text-[#f8fafc] group-hover:text-[#0284c7] dark:group-hover:text-[#38bdf8] truncate pr-2">
                    {u.value}
                  </span>
                  <span className="text-[10px] font-mono text-slate-600 dark:text-slate-400 bg-[#f1f5f9] dark:bg-[#0f172a] px-1.5 py-0.5 rounded border border-[#cbd5e1] dark:border-[#334155]">
                    {u.count.toLocaleString()} occurrences
                  </span>
                </button>
              ))
            ) : (
              <span className="text-xs text-slate-400 italic p-2">No user accounts indexed</span>
            )}
          </div>
        </div>

        {/* Column 2: Top Domains & URLs */}
        <div className="p-3.5 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded shadow-2xs flex flex-col">
          <div className="flex items-center justify-between pb-2 border-b border-[#cbd5e1] dark:border-[#334155] text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
            <div className="flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
              <span>Top Domains & URLs</span>
            </div>
            <button
              onClick={() => onExploreArtifact('REFINED RESULTS', 'view_refined_domains')}
              className="text-[11px] text-[#0284c7] dark:text-[#38bdf8] hover:underline flex items-center gap-0.5 font-mono cursor-pointer"
            >
              <span>View All</span>
              <ExternalLink className="w-2.5 h-2.5" />
            </button>
          </div>
          <div className="mt-2.5 space-y-1">
            {dashboard.top_domains && dashboard.top_domains.length > 0 ? (
              dashboard.top_domains.map((d, i) => (
                <button
                  key={i}
                  onClick={() =>
                    onInspectEntity
                      ? onInspectEntity(d.value)
                      : onExploreArtifact('REFINED RESULTS', 'view_refined_domains')
                  }
                  className="w-full flex items-center justify-between p-1.5 rounded hover:bg-[#f1f5f9] dark:hover:bg-[#334155] text-left transition-colors group cursor-pointer"
                >
                  <span className="text-xs font-mono text-[#0f172a] dark:text-[#f8fafc] group-hover:text-[#0284c7] dark:group-hover:text-[#38bdf8] truncate pr-2">
                    {d.value}
                  </span>
                  <span className="text-[10px] font-mono text-slate-600 dark:text-slate-400 bg-[#f1f5f9] dark:bg-[#0f172a] px-1.5 py-0.5 rounded border border-[#cbd5e1] dark:border-[#334155]">
                    {d.count.toLocaleString()} visits
                  </span>
                </button>
              ))
            ) : (
              <span className="text-xs text-slate-400 italic p-2">No domains indexed</span>
            )}
          </div>
        </div>

        {/* Column 3: Top Executables */}
        <div className="p-3.5 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded shadow-2xs flex flex-col">
          <div className="flex items-center justify-between pb-2 border-b border-[#cbd5e1] dark:border-[#334155] text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
            <div className="flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
              <span>Top Executables</span>
            </div>
            <button
              onClick={() => onExploreArtifact('OPERATING SYSTEM', 'raw_pecmd')}
              className="text-[11px] text-[#0284c7] dark:text-[#38bdf8] hover:underline flex items-center gap-0.5 font-mono cursor-pointer"
            >
              <span>View All</span>
              <ExternalLink className="w-2.5 h-2.5" />
            </button>
          </div>
          <div className="mt-2.5 space-y-1">
            {dashboard.top_executables && dashboard.top_executables.length > 0 ? (
              dashboard.top_executables.map((exe, i) => (
                <button
                  key={i}
                  onClick={() =>
                    onInspectEntity
                      ? onInspectEntity(exe.value)
                      : onExploreArtifact('OPERATING SYSTEM', 'raw_pecmd')
                  }
                  className="w-full flex items-center justify-between p-1.5 rounded hover:bg-[#f1f5f9] dark:hover:bg-[#334155] text-left transition-colors group cursor-pointer"
                >
                  <span className="text-xs font-mono text-[#0f172a] dark:text-[#f8fafc] group-hover:text-[#0284c7] dark:group-hover:text-[#38bdf8] truncate pr-2">
                    {exe.value}
                  </span>
                  <span className="text-[10px] font-mono text-slate-600 dark:text-slate-400 bg-[#f1f5f9] dark:bg-[#0f172a] px-1.5 py-0.5 rounded border border-[#cbd5e1] dark:border-[#334155]">
                    {exe.count.toLocaleString()} runs
                  </span>
                </button>
              ))
            ) : (
              <span className="text-xs text-slate-400 italic p-2">No executables indexed</span>
            )}
          </div>
        </div>
      </div>

      {/* 6. Recent Examiner Bookmarks & Notes */}
      {dashboard.bookmarks && dashboard.bookmarks.length > 0 && (
        <div className="mt-6 p-3.5 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded shadow-2xs flex flex-col">
          <div className="flex items-center justify-between pb-2 border-b border-[#cbd5e1] dark:border-[#334155] text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
            <div className="flex items-center gap-1.5">
              <BookmarkIcon className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
              <span>Examiner Tagged Evidence & Bookmarks ({dashboard.bookmarks.length})</span>
            </div>
          </div>
          <div className="mt-3 grid grid-cols-1 content-start auto-rows-max items-start md:grid-cols-2 lg:grid-cols-3 gap-2.5">
            {dashboard.bookmarks.map((b) => (
              <div
                key={b.bookmark_id}
                className="p-2.5 rounded bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] flex flex-col gap-1 text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="px-1.5 py-0.5 rounded bg-white dark:bg-[#1e293b] text-[#0284c7] dark:text-[#38bdf8] font-mono text-[10px] font-bold border border-[#cbd5e1] dark:border-[#334155]">
                    {b.tag_name}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">
                    Row #{b.source_row_id} in {b.source_table}
                  </span>
                </div>
                {b.examiner_notes && (
                  <p className="text-slate-600 dark:text-slate-300 italic text-[11px] mt-1">"{b.examiner_notes}"</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
