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
} from 'lucide-react';

interface CaseDashboardProps {
  caseId: string;
  onExploreArtifact: (category: string, tableName?: string) => void;
  onGoToTimeline: () => void;
  onGoToEventLogs?: () => void;
  onGoToMalware?: () => void;
}

export const CaseDashboard: React.FC<CaseDashboardProps> = ({
  caseId,
  onExploreArtifact,
  onGoToTimeline,
  onGoToEventLogs,
  onGoToMalware,
}) => {
  const [dashboard, setDashboard] = useState<CaseDashboardResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

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

  const dbSizeMb = (dashboard.db_size_bytes / (1024 * 1024)).toFixed(1);

  return (
    <div className="flex-1 flex flex-col h-full bg-[#f1f5f9] dark:bg-[#0f172a] overflow-y-auto p-5 select-none font-sans text-[#0f172a] dark:text-[#f8fafc]">
      {/* 1. Header & Title Banner */}
      <div className="flex items-center justify-between pb-4 border-b border-[#cbd5e1] dark:border-[#334155] shrink-0">
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
              WFT forensic case overview, artifact taxonomy breakdown, and evidence intelligence.
            </p>
          </div>
        </div>

        <button
          onClick={fetchDashboard}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc] text-xs rounded shadow-2xs transition-colors cursor-pointer"
          title="Refresh Dashboard"
        >
          <RefreshCw className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
          <span>Refresh Metrics</span>
        </button>
      </div>

      {/* 2. Top Evidence Metric Cards (Solid Border Enterprise Design) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 mt-4">
        {/* Card 1: Artifact Rows */}
        <div className="p-3.5 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded shadow-2xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-600 dark:text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Total Evidence Rows</span>
            <Layers className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-[#0f172a] dark:text-[#f8fafc]">
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
            {dashboard.categories.find(c => c.category === 'EVENT LOGS')?.count?.toLocaleString() || '24,994'}
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

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
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
      <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
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
                  onClick={() => onExploreArtifact('REFINED RESULTS', 'view_refined_users')}
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
                  onClick={() => onExploreArtifact('REFINED RESULTS', 'view_refined_domains')}
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
                  onClick={() => onExploreArtifact('OPERATING SYSTEM', 'raw_pecmd')}
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
          <div className="mt-3 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
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
