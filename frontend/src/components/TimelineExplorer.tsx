import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import {
  Clock,
  Search,
  RefreshCw,
  Activity,
  Info,
  ArrowUpDown,
  Crosshair,
  X,
  AlertTriangle,
  ExternalLink,
  Network,
} from 'lucide-react';
import {
  apiClient,
  TimelineResponse,
  TimelineEvent,
} from '../api/client';
import { useResizable, ResizeHandle } from './ResizeHandle';
import { RowContextMenu } from './RowContextMenu';
import { CANONICAL_WFT_CATEGORIES } from './SidebarTree';

const TIMELINE_CATEGORIES = [...CANONICAL_WFT_CATEGORIES, 'FILE SYSTEM'] as const;

interface TimelineExplorerProps {
  caseId: string;
  onNavigateToArtifact?: (tableName: string, rowId?: number | null) => void;
  onInspectEntity?: (entityValue: string) => void;
  globalSearch?: string;
  dateRange?: {
    preset?: string;
    startUtc?: string;
    endUtc?: string;
  };
  externalKeywords?: string[];
  tags?: string[];
  bookmarkedOnly?: boolean;
  externalPivot?: { aroundTimestamp: string; windowMinutes: number } | null;
  onClearExternalPivot?: () => void;
}

function parseUtcMs(ts?: string | null): number | null {
  if (!ts) return null;
  const trimmed = ts.trim();
  if (!trimmed) return null;
  const iso = trimmed.includes('T') ? trimmed : trimmed.replace(' ', 'T');
  const withZone = /Z$|[+-]\d{2}:?\d{2}$/i.test(iso) ? iso : `${iso}Z`;
  const ms = Date.parse(withZone);
  return Number.isNaN(ms) ? null : ms;
}

function deriveMacbFlags(event: TimelineEvent): Record<'M' | 'A' | 'C' | 'B', boolean> {
  const rawMacb = (event.macb || '').toUpperCase();
  if (rawMacb && /[MACB]/.test(rawMacb)) {
    return {
      M: rawMacb.includes('M'),
      A: rawMacb.includes('A'),
      C: rawMacb.includes('C'),
      B: rawMacb.includes('B'),
    };
  }
  const t = (event.timestamp_type || '').toLowerCase();
  const M = /modif|write|mtime/.test(t);
  const A = /access|atime|exec|run|visit|open|logon|focus/.test(t);
  const C = /change|entry|mft|meta|ctime|record/.test(t);
  const B = /birth|creat|born|btime|install|start/.test(t);
  if (!M && !A && !C && !B) {
    return { M: true, A: false, C: false, B: false };
  }
  return { M, A, C, B };
}

export const TimelineExplorer: React.FC<TimelineExplorerProps> = ({
  caseId,
  onNavigateToArtifact,
  onInspectEntity,
  globalSearch = '',
  dateRange,
  externalKeywords = [],
  tags = [],
  bookmarkedOnly = false,
  externalPivot = null,
  onClearExternalPivot,
}) => {
  const [data, setData] = useState<TimelineResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters & State
  const [searchInput, setSearchInput] = useState(globalSearch);
  const [debouncedSearch, setDebouncedSearch] = useState(globalSearch);
  const [category, setCategory] = useState('');
  const [startTime, setStartTime] = useState(dateRange?.startUtc || '');
  const [endTime, setEndTime] = useState(dateRange?.endUtc || '');
  const [sortDir, setSortDir] = useState<'desc' | 'asc'>('desc');
  const [macbFilter, setMacbFilter] = useState<Array<'M' | 'A' | 'C' | 'B'>>([]);
  const [pivotState, setPivotState] = useState<{ aroundTimestamp: string; windowMinutes: number } | null>(
    externalPivot
  );
  const [timelineEvents, setTimelineEvents] = useState<TimelineEvent[]>([]);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const pageSize = 250;

  // Selected event for detail view
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);

  // Right-Click Context Menu State
  const [contextMenu, setContextMenu] = useState<{
    position: { x: number; y: number };
    row: Record<string, any>;
    cellValue?: unknown;
  } | null>(null);

  // Resizable Right Event Inspector Pane
  const containerRef = useRef<HTMLDivElement>(null);
  const rightPane = useResizable({
    initialWidth: 360,
    minWidth: 260,
    maxWidth: 700,
    storageKey: 'wft_timeline_right_width',
    direction: 'right',
    containerRef,
    minCenterWidth: 350,
  });

  // Sync global search
  useEffect(() => {
    setSearchInput(globalSearch || '');
    setDebouncedSearch(globalSearch || '');
  }, [globalSearch]);

  // Debounce local search input (300ms)
  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDebouncedSearch(searchInput);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [searchInput]);

  // Sync external pivot
  useEffect(() => {
    if (externalPivot) {
      setPivotState(externalPivot);
    }
  }, [externalPivot?.aroundTimestamp, externalPivot?.windowMinutes]);

  // Sync date range
  useEffect(() => {
    if (dateRange) {
      setStartTime(dateRange.startUtc || '');
      setEndTime(dateRange.endUtc || '');
    }
  }, [dateRange?.preset, dateRange?.startUtc, dateRange?.endUtc]);

  const toggleMacbLetter = (letter: 'M' | 'A' | 'C' | 'B') => {
    setMacbFilter((prev) =>
      prev.includes(letter) ? prev.filter((l) => l !== letter) : [...prev, letter]
    );
  };

  const handleClearPivot = () => {
    setPivotState(null);
    onClearExternalPivot?.();
  };

  const keywordsKey = useMemo(() => JSON.stringify(externalKeywords || []), [externalKeywords]);
  const tagsKey = useMemo(() => JSON.stringify(tags || []), [tags]);
  const macbKey = useMemo(() => macbFilter.join(','), [macbFilter]);
  const reqSeqRef = useRef(0);

  const fetchTimeline = useCallback(async (reset: boolean = true) => {
    if (!caseId) return;
    const mySeq = ++reqSeqRef.current;
    if (reset) {
      setIsLoading(true);
    } else {
      setIsLoadingMore(true);
    }
    setError(null);

    try {
      const offset = reset ? 0 : timelineEvents.length;
      const res = await apiClient.getMasterTimeline(caseId, {
        limit: pageSize,
        offset,
        search: debouncedSearch.trim() || undefined,
        category: category.trim() || undefined,
        sort_dir: sortDir,
        macb: macbFilter.length > 0 ? macbFilter : undefined,
        around_timestamp: pivotState?.aroundTimestamp || undefined,
        window_minutes: pivotState ? pivotState.windowMinutes : undefined,
        start_time: pivotState ? undefined : startTime.trim() || undefined,
        end_time: pivotState ? undefined : endTime.trim() || undefined,
        keywords: externalKeywords.length > 0 ? externalKeywords : undefined,
        tags: tags.length > 0 ? tags : undefined,
        bookmarked_only: bookmarkedOnly || undefined,
      });
      if (mySeq !== reqSeqRef.current) return;
      setData(res);
      if (reset) {
        setTimelineEvents(res.timeline || []);
        if (res.timeline && res.timeline.length > 0) {
          setSelectedEvent(res.timeline[0]);
        } else {
          setSelectedEvent(null);
        }
      } else {
        setTimelineEvents((prev) => [...prev, ...(res.timeline || [])]);
      }
    } catch (err: unknown) {
      if (mySeq !== reqSeqRef.current) return;
      setError(err instanceof Error ? err.message : String(err));
      if (reset) {
        setData(null);
        setTimelineEvents([]);
        setSelectedEvent(null);
      }
    } finally {
      if (mySeq === reqSeqRef.current) {
        setIsLoading(false);
        setIsLoadingMore(false);
      }
    }
  }, [
    caseId,
    pageSize,
    timelineEvents.length,
    debouncedSearch,
    category,
    sortDir,
    macbKey,
    pivotState?.aroundTimestamp,
    pivotState?.windowMinutes,
    startTime,
    endTime,
    keywordsKey,
    tagsKey,
    bookmarkedOnly,
  ]);

  useEffect(() => {
    fetchTimeline(true);
  }, [
    caseId,
    debouncedSearch,
    category,
    sortDir,
    macbKey,
    pivotState?.aroundTimestamp,
    pivotState?.windowMinutes,
    startTime,
    endTime,
    keywordsKey,
    tagsKey,
    bookmarkedOnly,
  ]);

  // Client-side fallback guarantee for Pivot window, MACB filter, OR keywords, and ASC/DESC sort
  const displayedEvents = useMemo(() => {
    let list = [...timelineEvents];

    if (pivotState?.aroundTimestamp) {
      const centerMs = parseUtcMs(pivotState.aroundTimestamp);
      if (centerMs !== null) {
        const halfWinMs = Math.max(1, pivotState.windowMinutes) * 60 * 1000;
        list = list.filter((ev) => {
          const evMs = parseUtcMs(ev.timestamp_utc);
          return evMs !== null && Math.abs(evMs - centerMs) <= halfWinMs;
        });
      }
    }

    if (macbFilter.length > 0) {
      list = list.filter((ev) => {
        const flags = deriveMacbFlags(ev);
        return macbFilter.some((letter) => flags[letter]);
      });
    }

    if (externalKeywords.length > 0) {
      const lowered = externalKeywords.map((k) => k.toLowerCase()).filter(Boolean);
      if (lowered.length > 0) {
        list = list.filter((ev) => {
          const hay = [
            ev.primary_entity,
            ev.secondary_entity,
            ev.summary,
            ev.artifact_name,
            ev.source_file,
            ev.category,
          ]
            .filter(Boolean)
            .join(' ')
            .toLowerCase();
          return lowered.some((kw) => hay.includes(kw));
        });
      }
    }

    list.sort((a, b) => {
      const ta = a.timestamp_utc || '';
      const tb = b.timestamp_utc || '';
      return sortDir === 'asc' ? ta.localeCompare(tb) : tb.localeCompare(ta);
    });

    return list;
  }, [timelineEvents, pivotState, macbFilter, externalKeywords, sortDir]);

  useEffect(() => {
    if (selectedEvent && !displayedEvents.some((ev) => ev.timeline_id === selectedEvent.timeline_id)) {
      setSelectedEvent(displayedEvents.length > 0 ? displayedEvents[0] : null);
    } else if (!selectedEvent && displayedEvents.length > 0) {
      setSelectedEvent(displayedEvents[0]);
    }
  }, [displayedEvents, selectedEvent]);

  // Max histogram count for scaling bars
  const maxHistogramCount = useMemo(() => {
    if (!data?.histogram || data.histogram.length === 0) return 1;
    return Math.max(...data.histogram.map((h) => h.count), 1);
  }, [data?.histogram]);

  return (
    <div className="flex flex-col h-full bg-[#f1f5f9] dark:bg-[#0f172a] text-[#0f172a] dark:text-[#f8fafc] overflow-hidden select-none font-sans">
      {/* Top Filter Toolbar */}
      <div className="p-2.5 bg-white dark:bg-[#1e293b] border-b border-[#cbd5e1] dark:border-[#334155] flex flex-wrap items-center justify-between gap-3 shrink-0 shadow-2xs">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
          <span className="font-bold text-xs text-[#0f172a] dark:text-[#f8fafc]">Chronological Super-Timeline</span>
          {data && (
            <span className="text-[11px] font-mono text-[#0284c7] dark:text-[#38bdf8]">
              ({displayedEvents.length.toLocaleString()} shown / {data.filtered_count.toLocaleString()} matched)
            </span>
          )}
        </div>

        {/* Filter Inputs */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* MACB Quick Filter Pills */}
          <div className="flex items-center gap-0.5 bg-[#f8fafc] dark:bg-[#0f172a] p-0.5 rounded border border-[#cbd5e1] dark:border-[#334155]">
            {(['M', 'A', 'C', 'B'] as const).map((letter) => {
              const active = macbFilter.includes(letter);
              const titleMap = {
                M: 'Modified (Last Write)',
                A: 'Accessed / Executed',
                C: 'MFT Entry / Metadata Changed',
                B: 'Born / Created',
              };
              return (
                <button
                  key={letter}
                  type="button"
                  data-testid={`timeline-macb-filter-${letter}`}
                  onClick={() => toggleMacbLetter(letter)}
                  title={`Filter MACB: ${titleMap[letter]}`}
                  className={`px-1.5 py-0.5 text-[10px] font-mono font-bold rounded cursor-pointer transition-colors ${
                    active
                      ? 'bg-[#0284c7] text-white'
                      : 'text-slate-500 hover:bg-slate-200 dark:hover:bg-slate-800'
                  }`}
                >
                  {letter}
                </button>
              );
            })}
          </div>

          {/* Sort Direction Toggle */}
          <button
            type="button"
            data-testid="timeline-sort-toggle"
            onClick={() => setSortDir((prev) => (prev === 'desc' ? 'asc' : 'desc'))}
            className="flex items-center gap-1 px-2 py-1 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#334155] text-xs font-mono font-semibold cursor-pointer transition-colors"
            title="Toggle chronological sort order (ASC / DESC)"
          >
            <ArrowUpDown className="w-3 h-3 text-[#0284c7] dark:text-[#38bdf8]" />
            <span>{sortDir === 'desc' ? 'DESC ↓' : 'ASC ↑'}</span>
          </button>

          {/* Category Filter */}
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc] text-xs rounded px-2 py-1 font-mono focus:border-[#0284c7] focus:outline-none"
          >
            <option value="">All Categories</option>
            {TIMELINE_CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>

          {/* Search Box */}
          <div className="relative w-48">
            <Search className="w-3 h-3 absolute left-2 top-2 text-slate-400" />
            <input
              type="text"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') setDebouncedSearch(searchInput);
              }}
              placeholder="Search timeline..."
              className="w-full bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded pl-7 pr-2 py-1 text-xs text-[#0f172a] dark:text-[#f8fafc] placeholder-slate-400 font-mono focus:border-[#0284c7] focus:outline-none"
            />
          </div>

          {/* Date Range Pickers */}
          <div className="flex items-center gap-1 text-xs font-mono text-slate-600 dark:text-slate-400">
            <span className="text-[10px]">From:</span>
            <input
              type="date"
              value={startTime.slice(0, 10)}
              onChange={(e) => setStartTime(e.target.value)}
              className="bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded px-1.5 py-0.5 text-xs text-[#0f172a] dark:text-[#f8fafc] font-mono focus:outline-none"
            />
            <span className="text-[10px]">To:</span>
            <input
              type="date"
              value={endTime.slice(0, 10)}
              onChange={(e) => setEndTime(e.target.value)}
              className="bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded px-1.5 py-0.5 text-xs text-[#0f172a] dark:text-[#f8fafc] font-mono focus:outline-none"
            />
            {(startTime || endTime || category || searchInput || macbFilter.length > 0 || pivotState) && (
              <button
                type="button"
                onClick={() => {
                  setStartTime('');
                  setEndTime('');
                  setCategory('');
                  setSearchInput('');
                  setDebouncedSearch('');
                  setMacbFilter([]);
                  handleClearPivot();
                }}
                className="text-[10px] text-[#0284c7] dark:text-[#38bdf8] hover:underline px-1 cursor-pointer font-semibold"
              >
                Reset
              </button>
            )}
          </div>

          {/* Continuous View Badge & Refresh */}
          <div className="flex items-center gap-2 text-xs font-mono pl-2 border-l border-[#cbd5e1] dark:border-[#334155]">
            <button
              type="button"
              onClick={() => fetchTimeline(true)}
              disabled={isLoading}
              className="p-1 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#334155] transition-colors cursor-pointer"
              title="Refresh Timeline"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-[#0284c7]' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* Magnet AXIOM Active Temporal Pivot Banner */}
      {pivotState && (
        <div
          data-testid="timeline-pivot-banner"
          className="px-3 py-2 bg-sky-50 dark:bg-sky-950/50 border-b border-sky-300 dark:border-sky-800 flex flex-wrap items-center justify-between gap-2 shrink-0"
        >
          <div className="flex items-center gap-2 text-xs font-mono text-[#0369a1] dark:text-[#38bdf8]">
            <Crosshair className="w-4 h-4 shrink-0" />
            <span className="font-bold">
              Pivoting around {pivotState.aroundTimestamp.replace('T', ' ').slice(0, 19)} UTC (±{pivotState.windowMinutes}m)
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            {[1, 5, 15, 60].map((win) => (
              <button
                key={win}
                type="button"
                onClick={() =>
                  setPivotState({ aroundTimestamp: pivotState.aroundTimestamp, windowMinutes: win })
                }
                className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold border cursor-pointer transition-colors ${
                  pivotState.windowMinutes === win
                    ? 'bg-[#0284c7] text-white border-[#0284c7]'
                    : 'bg-white dark:bg-[#0f172a] text-slate-600 dark:text-slate-300 border-[#cbd5e1] dark:border-[#334155] hover:border-[#0284c7]'
                }`}
              >
                {win === 60 ? '±1h' : `±${win}m`}
              </button>
            ))}
            <button
              type="button"
              data-testid="timeline-clear-pivot-btn"
              onClick={handleClearPivot}
              className="ml-1 px-2.5 py-0.5 rounded bg-white hover:bg-rose-50 dark:bg-[#0f172a] dark:hover:bg-rose-950/40 text-rose-600 dark:text-rose-400 border border-rose-300 dark:border-rose-800 text-[11px] font-bold flex items-center gap-1 cursor-pointer"
            >
              <X className="w-3 h-3" />
              <span>Clear Pivot</span>
            </button>
          </div>
        </div>
      )}

      {/* Date Histogram Visualization Bar */}
      {data?.histogram && data.histogram.length > 0 && (
        <div className="bg-white dark:bg-[#1e293b] px-3 py-2 border-b border-[#cbd5e1] dark:border-[#334155] shrink-0">
          <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 dark:text-slate-400 mb-1">
            <span className="flex items-center gap-1 font-semibold text-[#0f172a] dark:text-[#f8fafc]">
              <Activity className="w-3 h-3 text-[#0284c7] dark:text-[#38bdf8]" />
              Event Volume Distribution ({data.histogram.length} Active Days)
            </span>
            <span>Click bucket to filter range</span>
          </div>

          <div className="h-12 flex items-end gap-1 overflow-x-auto pb-1">
            {data.histogram.map((bucket) => {
              const heightPct = Math.max(10, Math.round((bucket.count / maxHistogramCount) * 100));
              const isSelectedDay = startTime.startsWith(bucket.day.slice(0, 10));

              return (
                <button
                  key={bucket.day}
                  onClick={() => {
                    const dayPrefix = bucket.day.slice(0, 10);
                    setStartTime(`${dayPrefix} 00:00:00`);
                    setEndTime(`${dayPrefix} 23:59:59`);
                  }}
                  className="flex-1 min-w-[12px] max-w-[28px] h-full flex flex-col justify-end items-center group relative cursor-pointer"
                  title={`${bucket.day.slice(0, 10)}: ${bucket.count.toLocaleString()} events`}
                >
                  <div
                    className={`w-full rounded-t transition-all ${
                      isSelectedDay
                        ? 'bg-[#0369a1] dark:bg-[#38bdf8] shadow-2xs'
                        : 'bg-[#0284c7]/70 hover:bg-[#0284c7] dark:bg-[#38bdf8]/60 dark:hover:bg-[#38bdf8]'
                    }`}
                    style={{ height: `${heightPct}%` }}
                  />
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Main Content Split: Timeline Table & Selected Event Inspector */}
      <div ref={containerRef} className="flex-1 flex flex-col lg:flex-row overflow-hidden relative">
        {isLoading && (
          <div className="absolute inset-0 bg-white/70 dark:bg-[#0f172a]/70 z-20 flex items-center justify-center">
            <div className="flex flex-col items-center gap-2">
              <RefreshCw className="w-6 h-6 text-[#0284c7] dark:text-[#38bdf8] animate-spin" />
              <span className="text-xs font-mono text-slate-600 dark:text-slate-300">Loading Super-Timeline...</span>
            </div>
          </div>
        )}

        {/* Timeline Event Feed / Grid with Continuous Scrolling */}
        <div
          onScroll={(e) => {
            const t = e.currentTarget;
            if (
              t.scrollHeight - t.scrollTop - t.clientHeight < 300 &&
              !isLoading &&
              !isLoadingMore &&
              data &&
              timelineEvents.length < data.filtered_count
            ) {
              fetchTimeline(false);
            }
          }}
          className="flex-1 overflow-y-auto bg-white dark:bg-[#1e293b]"
        >
          {error ? (
            <div className="p-8 text-center text-[#991b1b] dark:text-red-400 text-xs font-mono">{error}</div>
          ) : displayedEvents.length === 0 && !isLoading ? (
            <div className="p-8 text-center text-slate-500 italic text-xs">
              No timeline events found matching the active criteria.
            </div>
          ) : (
            <>
              <table className="w-full border-collapse text-left font-mono text-xs">
                <thead className="sticky top-0 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] text-[10px] text-slate-600 dark:text-slate-400 uppercase tracking-wider z-10">
                  <tr>
                    <th
                      onClick={() => setSortDir((prev) => (prev === 'desc' ? 'asc' : 'desc'))}
                      className="py-2 px-3 w-48 font-semibold cursor-pointer hover:text-[#0284c7] select-none"
                      title="Click to toggle chronological sort direction"
                    >
                      Timestamp (UTC) {sortDir === 'desc' ? '↓' : '↑'}
                    </th>
                    <th className="py-2 px-2 w-24 font-semibold">MACB</th>
                    <th className="py-2 px-2 w-36 font-semibold">Type</th>
                    <th className="py-2 px-2 w-32 font-semibold">Category</th>
                    <th className="py-2 px-2 w-48 font-semibold">Primary Entity</th>
                    <th className="py-2 px-3 font-semibold">Event Summary</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#e2e8f0] dark:divide-[#334155]">
                  {displayedEvents.map((event) => {
                    const isSelected = selectedEvent?.timeline_id === event.timeline_id;
                    const macbFlags = deriveMacbFlags(event);
                    return (
                      <tr
                        key={event.timeline_id}
                        onClick={() => setSelectedEvent(event)}
                        onContextMenu={(e) => {
                          e.preventDefault();
                          setSelectedEvent(event);
                          setContextMenu({
                            position: { x: e.clientX, y: e.clientY },
                            row: {
                              ...event,
                              _row_id: event.source_row_id,
                              _table_name: event.source_table,
                              file_path: event.source_file,
                            },
                            cellValue: event.artifact_name || event.summary,
                          });
                        }}
                        className={`cursor-pointer transition-colors group ${
                          isSelected
                            ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] border-l-4 border-l-[#0284c7] dark:border-l-[#38bdf8] text-[#0f172a] dark:text-[#f8fafc]'
                            : 'hover:bg-slate-50 dark:hover:bg-[#334155]'
                        }`}
                      >
                        <td className="py-1.5 px-3 font-semibold whitespace-nowrap text-[11px] text-[#0f172a] dark:text-[#f8fafc]">
                          <div className="flex items-center gap-1.5">
                            <span>{event.timestamp_utc?.replace('T', ' ').slice(0, 19)}</span>
                            {event.timestamp_utc && (
                              <button
                                type="button"
                                data-testid={`timeline-row-pivot-${event.timeline_id}`}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setPivotState({
                                    aroundTimestamp: event.timestamp_utc,
                                    windowMinutes: 5,
                                  });
                                }}
                                title="Pivot ±5m around this timestamp"
                                className="opacity-70 hover:opacity-100 px-1 py-0.2 rounded bg-sky-100 hover:bg-sky-200 dark:bg-sky-950/60 text-[#0284c7] dark:text-[#38bdf8] text-[9px] font-bold cursor-pointer"
                              >
                                ±5m
                              </button>
                            )}
                          </div>
                        </td>

                        <td className="py-1.5 px-2 whitespace-nowrap">
                          <div className="inline-flex items-center gap-0.5" data-testid="timeline-macb-badges">
                            {(['M', 'A', 'C', 'B'] as const).map((slot) => {
                              const on = macbFlags[slot];
                              const colorCls =
                                slot === 'M'
                                  ? 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/70 dark:text-amber-300 dark:border-amber-800'
                                  : slot === 'A'
                                  ? 'bg-sky-100 text-sky-800 border-sky-300 dark:bg-sky-950/70 dark:text-sky-300 dark:border-sky-800'
                                  : slot === 'C'
                                  ? 'bg-purple-100 text-purple-800 border-purple-300 dark:bg-purple-950/70 dark:text-purple-300 dark:border-purple-800'
                                  : 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/70 dark:text-emerald-300 dark:border-emerald-800';
                              return (
                                <span
                                  key={slot}
                                  className={`w-4 h-4 inline-flex items-center justify-center rounded text-[9px] font-bold border ${
                                    on
                                      ? colorCls
                                      : 'bg-slate-50 text-slate-300 border-slate-200 dark:bg-slate-900 dark:text-slate-600 dark:border-slate-800'
                                  }`}
                                >
                                  {on ? slot : '.'}
                                </span>
                              );
                            })}
                            {event.timestomped && (
                              <span
                                className="ml-1 px-1 py-0.2 rounded bg-rose-100 dark:bg-rose-950/80 text-rose-700 dark:text-rose-300 border border-rose-300 dark:border-rose-800 text-[9px] font-extrabold inline-flex items-center gap-0.5"
                                title="Potential NTFS Timestomping ($SI < $FN)"
                              >
                                <AlertTriangle className="w-2.5 h-2.5" />
                                <span>TIMESTOMP</span>
                              </span>
                            )}
                          </div>
                        </td>

                        <td className="py-1.5 px-2">
                          <span className="px-1.5 py-0.2 rounded text-[10px] bg-white dark:bg-[#0f172a] text-slate-700 dark:text-slate-300 border border-[#cbd5e1] dark:border-[#334155] truncate max-w-[130px] inline-block">
                            {event.timestamp_type}
                          </span>
                        </td>

                        <td className="py-1.5 px-2 text-slate-600 dark:text-slate-400 text-[11px] truncate max-w-[120px]">
                          {event.category}
                        </td>

                        <td className="py-1.5 px-2">
                          <div className="flex items-center justify-between overflow-hidden">
                            {event.primary_entity ? (
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  onInspectEntity?.(event.primary_entity!);
                                }}
                                className="font-bold text-[#0284c7] dark:text-[#38bdf8] hover:underline truncate max-w-[170px] text-[11px] cursor-pointer text-left"
                                title={`Inspect "${event.primary_entity}" in Connections Graph`}
                              >
                                {event.primary_entity}
                              </button>
                            ) : (
                              <span className="text-slate-400 text-[11px]">—</span>
                            )}
                          </div>
                        </td>

                        <td className="py-1.5 px-3 text-slate-700 dark:text-slate-300 text-[11px] truncate max-w-md">
                          {event.summary || event.secondary_entity || '—'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>

              {isLoadingMore && (
                <div className="py-4 text-center text-xs font-mono text-[#0284c7] flex items-center justify-center gap-2">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Loading more events in same page...</span>
                </div>
              )}
            </>
          )}
        </div>

        {/* DRAGGABLE VERTICAL SPLITTER (Between Timeline Grid and Event Inspector) */}
        {selectedEvent && (
          <ResizeHandle
            orientation="vertical"
            onMouseDown={rightPane.handleMouseDown}
            onDoubleClick={rightPane.resetWidth}
            isDragging={rightPane.isDragging}
            title="Drag to resize Event Inspector pane (double-click to reset)"
          />
        )}

        {/* Selected Event Details Inspector (Right Side or Bottom) */}
        {selectedEvent && (
          <div
            style={{ width: `${rightPane.width}px` }}
            className="w-full lg:w-auto border-t lg:border-t-0 lg:border-l border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] p-3 flex flex-col gap-3 shrink-0 overflow-y-auto"
          >
            <div className="flex items-center justify-between pb-2 border-b border-[#cbd5e1] dark:border-[#334155]">
              <span className="text-xs font-bold text-[#0f172a] dark:text-[#f8fafc] flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
                Event Inspector
              </span>
              <span className="text-[10px] font-mono text-slate-500">
                #{selectedEvent.timeline_id}
              </span>
            </div>

            <div className="flex flex-col gap-2 font-mono text-xs">
              <div className="bg-[#f8fafc] dark:bg-[#0f172a] p-2 rounded border border-[#cbd5e1] dark:border-[#334155] space-y-1.5">
                <span className="text-[10px] text-slate-500 block">UTC TIMESTAMP &amp; WINDOW</span>
                <span className="font-bold text-[#0f172a] dark:text-[#f8fafc] block">
                  {selectedEvent.timestamp_utc?.replace('T', ' ')}
                </span>
                {selectedEvent.timestamp_utc && (
                  <div className="flex items-center gap-1 pt-1 flex-wrap">
                    {[1, 5, 15, 60].map((win) => (
                      <button
                        key={win}
                        type="button"
                        data-testid={`inspector-pivot-${win}m`}
                        onClick={() =>
                          setPivotState({
                            aroundTimestamp: selectedEvent.timestamp_utc,
                            windowMinutes: win,
                          })
                        }
                        className="px-1.5 py-0.5 rounded bg-sky-50 hover:bg-sky-100 dark:bg-sky-950/60 dark:hover:bg-sky-900/60 text-[#0284c7] dark:text-[#38bdf8] border border-sky-200 dark:border-sky-800 text-[10px] font-bold cursor-pointer"
                      >
                        Window {win === 60 ? '±1h' : `±${win}m`}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <div className="bg-[#f8fafc] dark:bg-[#0f172a] p-2 rounded border border-[#cbd5e1] dark:border-[#334155]">
                <span className="text-[10px] text-slate-500 block">TIMESTAMP TYPE</span>
                <span className="text-[#0284c7] dark:text-[#38bdf8] font-semibold">{selectedEvent.timestamp_type}</span>
              </div>

              <div className="bg-[#f8fafc] dark:bg-[#0f172a] p-2 rounded border border-[#cbd5e1] dark:border-[#334155]">
                <span className="text-[10px] text-slate-500 block">ARTIFACT / CATEGORY</span>
                <span className="text-[#0f172a] dark:text-[#f8fafc] font-semibold">{selectedEvent.artifact_name}</span>
                <span className="text-slate-500 dark:text-slate-400 text-[10px] block">({selectedEvent.category})</span>
              </div>

              {selectedEvent.primary_entity && (
                <div className="bg-[#f8fafc] dark:bg-[#0f172a] p-2 rounded border border-[#cbd5e1] dark:border-[#334155]">
                  <span className="text-[10px] text-slate-500 block">PRIMARY ENTITY</span>
                  <div className="mt-0.5 flex items-center justify-between gap-2">
                    <button
                      type="button"
                      onClick={() => onInspectEntity?.(selectedEvent.primary_entity!)}
                      className="text-[#0284c7] dark:text-[#38bdf8] hover:underline font-bold truncate text-left cursor-pointer"
                    >
                      {selectedEvent.primary_entity}
                    </button>
                    <button
                      type="button"
                      onClick={() => onInspectEntity?.(selectedEvent.primary_entity!)}
                      className="p-1 rounded hover:bg-sky-100 dark:hover:bg-sky-900/50 text-[#0284c7] dark:text-[#38bdf8] shrink-0 cursor-pointer"
                      title="Inspect in Connections Graph"
                    >
                      <Network className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              )}

              {selectedEvent.secondary_entity && (
                <div className="bg-[#f8fafc] dark:bg-[#0f172a] p-2 rounded border border-[#cbd5e1] dark:border-[#334155]">
                  <span className="text-[10px] text-slate-500 block">SECONDARY ENTITY</span>
                  <button
                    type="button"
                    onClick={() => onInspectEntity?.(selectedEvent.secondary_entity!)}
                    className="text-slate-700 dark:text-slate-300 hover:text-[#0284c7] hover:underline break-words text-left cursor-pointer"
                  >
                    {selectedEvent.secondary_entity}
                  </button>
                </div>
              )}

              <div className="bg-[#f8fafc] dark:bg-[#0f172a] p-2 rounded border border-[#cbd5e1] dark:border-[#334155] space-y-1">
                <span className="text-[10px] text-slate-500 block">SOURCE PROVENANCE</span>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-slate-700 dark:text-slate-300 block">
                    Table: <span className="font-bold">{selectedEvent.source_table}</span> (Row #{selectedEvent.source_row_id})
                  </span>
                  {onNavigateToArtifact && selectedEvent.source_table && (
                    <button
                      type="button"
                      onClick={() =>
                        onNavigateToArtifact(selectedEvent.source_table, selectedEvent.source_row_id)
                      }
                      className="text-[10px] text-[#0284c7] dark:text-[#38bdf8] hover:underline inline-flex items-center gap-0.5 cursor-pointer shrink-0"
                    >
                      <span>Open</span>
                      <ExternalLink className="w-2.5 h-2.5" />
                    </button>
                  )}
                </div>
                {selectedEvent.source_file && (
                  <span className="text-[10px] text-slate-500 break-words block mt-0.5" title={selectedEvent.source_file}>
                    File: {selectedEvent.source_file}
                  </span>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Native Magnet AXIOM-style Right-Click Forensic Context Menu */}
      {contextMenu && (
        <RowContextMenu
          caseId={caseId}
          position={contextMenu.position}
          onClose={() => setContextMenu(null)}
          row={contextMenu.row}
          tableName={contextMenu.row.source_table || 'master_timeline'}
          cellValue={contextMenu.cellValue}
          onInspectEntity={onInspectEntity}
          onPivotTimeline={(ts, win) =>
            setPivotState({ aroundTimestamp: ts, windowMinutes: win ?? 5 })
          }
        />
      )}
    </div>
  );
};
