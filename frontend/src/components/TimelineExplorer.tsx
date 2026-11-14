import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import {
  Clock,
  Search,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  Activity,
  Info,
} from 'lucide-react';
import {
  apiClient,
  TimelineResponse,
  TimelineEvent,
} from '../api/client';
import { useResizable, ResizeHandle } from './ResizeHandle';
import { RowContextMenu } from './RowContextMenu';

interface TimelineExplorerProps {
  caseId: string;
  onInspectEntity?: (entityValue: string) => void;
  globalSearch?: string;
  dateRange?: {
    preset: string;
    startUtc?: string;
    endUtc?: string;
  };
}

export const TimelineExplorer: React.FC<TimelineExplorerProps> = ({
  caseId,
  onInspectEntity,
  globalSearch = '',
  dateRange,
}) => {
  const [data, setData] = useState<TimelineResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters & State
  const [search, setSearch] = useState(globalSearch);
  const [category, setCategory] = useState('');
  const [startTime, setStartTime] = useState(dateRange?.startUtc || '');
  const [endTime, setEndTime] = useState(dateRange?.endUtc || '');
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
    if (globalSearch !== undefined) {
      setSearch(globalSearch);
    }
  }, [globalSearch]);

  // Sync date range
  useEffect(() => {
    if (dateRange) {
      setStartTime(dateRange.startUtc || '');
      setEndTime(dateRange.endUtc || '');
    }
  }, [dateRange?.preset, dateRange?.startUtc, dateRange?.endUtc]);

  const fetchTimeline = useCallback(async (reset: boolean = true) => {
    if (!caseId) return;
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
        search: search.trim() || undefined,
        category: category.trim() || undefined,
        start_time: startTime.trim() || undefined,
        end_time: endTime.trim() || undefined,
      });
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
      setError(err instanceof Error ? err.message : String(err));
      if (reset) {
        setData(null);
        setTimelineEvents([]);
        setSelectedEvent(null);
      }
    } finally {
      setIsLoading(false);
      setIsLoadingMore(false);
    }
  }, [caseId, pageSize, timelineEvents.length, search, category, startTime, endTime]);

  useEffect(() => {
    fetchTimeline(true);
  }, [caseId, search, category, startTime, endTime]);

  // Max histogram count for scaling bars
  const maxHistogramCount = useMemo(() => {
    if (!data?.histogram || data.histogram.length === 0) return 1;
    return Math.max(...data.histogram.map((h) => h.count), 1);
  }, [data?.histogram]);

  const totalPages = data ? Math.ceil(data.filtered_count / pageSize) : 0;

  const categories = [
    'Program Execution',
    'Event Logs',
    'File System',
    'Registry & OS',
    'USB & External Devices',
    'Network & SRUM',
    'Web Browsers',
    'Chat & Collaboration',
    'Cloud Storage',
    'Email',
    'Malware & YARA',
    'Media & OCR',
  ];

  return (
    <div className="flex flex-col h-full bg-[#f1f5f9] dark:bg-[#0f172a] text-[#0f172a] dark:text-[#f8fafc] overflow-hidden select-none font-sans">
      {/* Top Filter Toolbar */}
      <div className="p-2.5 bg-white dark:bg-[#1e293b] border-b border-[#cbd5e1] dark:border-[#334155] flex flex-wrap items-center justify-between gap-3 shrink-0 shadow-2xs">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
          <span className="font-bold text-xs text-[#0f172a] dark:text-[#f8fafc]">Chronological Super-Timeline</span>
          {data && (
            <span className="text-[11px] font-mono text-[#0284c7] dark:text-[#38bdf8]">
              ({data.filtered_count.toLocaleString()} events
              {data.filtered_count !== data.total_count && ` of ${data.total_count.toLocaleString()}`})
            </span>
          )}
        </div>

        {/* Filter Inputs */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Category Filter */}
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc] text-xs rounded px-2 py-1 font-mono focus:border-[#0284c7] focus:outline-none"
          >
            <option value="">All Categories</option>
            {categories.map((c) => (
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
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search timeline..."
              className="w-full bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded pl-7 pr-2 py-1 text-xs text-[#0f172a] dark:text-[#f8fafc] placeholder-slate-400 font-mono focus:border-[#0284c7] focus:outline-none"
            />
          </div>

          {/* Date Range Pickers */}
          <div className="flex items-center gap-1 text-xs font-mono text-slate-600 dark:text-slate-400">
            <span className="text-[10px]">From:</span>
            <input
              type="date"
              value={startTime}
              onChange={(e) => setStartTime(e.target.value)}
              className="bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded px-1.5 py-0.5 text-xs text-[#0f172a] dark:text-[#f8fafc] font-mono focus:outline-none"
            />
            <span className="text-[10px]">To:</span>
            <input
              type="date"
              value={endTime}
              onChange={(e) => setEndTime(e.target.value)}
              className="bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded px-1.5 py-0.5 text-xs text-[#0f172a] dark:text-[#f8fafc] font-mono focus:outline-none"
            />
            {(startTime || endTime || category || search) && (
              <button
                onClick={() => {
                  setStartTime('');
                  setEndTime('');
                  setCategory('');
                  setSearch('');
                }}
                className="text-[10px] text-[#0284c7] dark:text-[#38bdf8] hover:underline px-1 cursor-pointer font-semibold"
              >
                Reset
              </button>
            )}
          </div>

          {/* Continuous View Badge & Refresh (NO page buttons!) */}
          <div className="flex items-center gap-2 text-xs font-mono pl-2 border-l border-[#cbd5e1] dark:border-[#334155]">
            {data && data.filtered_count > 0 && (
              <span className="hidden sm:inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-[11px] text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                <span>All {data.filtered_count.toLocaleString()} events in single view</span>
              </span>
            )}

            <button
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
          ) : timelineEvents.length === 0 && !isLoading ? (
            <div className="p-8 text-center text-slate-500 italic text-xs">
              No timeline events found matching the active criteria.
            </div>
          ) : (
            <>
              <table className="w-full border-collapse text-left font-mono text-xs">
                <thead className="sticky top-0 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] text-[10px] text-slate-600 dark:text-slate-400 uppercase tracking-wider z-10">
                  <tr>
                    <th className="py-2 px-3 w-44 font-semibold">Timestamp (UTC)</th>
                    <th className="py-2 px-2 w-36 font-semibold">Type</th>
                    <th className="py-2 px-2 w-32 font-semibold">Category</th>
                    <th className="py-2 px-2 w-48 font-semibold">Primary Entity</th>
                    <th className="py-2 px-3 font-semibold">Event Summary</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#e2e8f0] dark:divide-[#334155]">
                  {timelineEvents.map((event) => {
                    const isSelected = selectedEvent?.timeline_id === event.timeline_id;
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
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] border-l-4 border-l-[#0284c7] dark:border-l-[#38bdf8] text-[#0f172a] dark:text-[#f8fafc]'
                            : 'hover:bg-slate-50 dark:hover:bg-[#334155]'
                        }`}
                      >
                        <td className="py-1.5 px-3 font-semibold whitespace-nowrap text-[11px] text-[#0f172a] dark:text-[#f8fafc]">
                          {event.timestamp_utc?.replace('T', ' ').slice(0, 19)}
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
                          <div className="flex items-center justify-between group overflow-hidden">
                            <span
                              className="font-bold text-[#0284c7] dark:text-[#38bdf8] truncate max-w-[160px] text-[11px]"
                              title={event.primary_entity}
                            >
                              {event.primary_entity || '—'}
                            </span>
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
              <div className="bg-[#f8fafc] dark:bg-[#0f172a] p-2 rounded border border-[#cbd5e1] dark:border-[#334155]">
                <span className="text-[10px] text-slate-500 block">UTC TIMESTAMP</span>
                <span className="font-bold text-[#0f172a] dark:text-[#f8fafc]">
                  {selectedEvent.timestamp_utc?.replace('T', ' ')}
                </span>
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
                  <div className="mt-0.5">
                    <span className="text-[#0284c7] dark:text-[#38bdf8] font-bold truncate block select-all">
                      {selectedEvent.primary_entity}
                    </span>
                  </div>
                </div>
              )}

              {selectedEvent.secondary_entity && (
                <div className="bg-[#f8fafc] dark:bg-[#0f172a] p-2 rounded border border-[#cbd5e1] dark:border-[#334155]">
                  <span className="text-[10px] text-slate-500 block">SECONDARY ENTITY</span>
                  <span className="text-slate-700 dark:text-slate-300 break-all select-all">
                    {selectedEvent.secondary_entity}
                  </span>
                </div>
              )}

              <div className="bg-[#f8fafc] dark:bg-[#0f172a] p-2 rounded border border-[#cbd5e1] dark:border-[#334155]">
                <span className="text-[10px] text-slate-500 block">SOURCE PROVENANCE</span>
                <span className="text-slate-700 dark:text-slate-300 block">
                  Table: <span className="font-bold">{selectedEvent.source_table}</span> (Row #{selectedEvent.source_row_id})
                </span>
                {selectedEvent.source_file && (
                  <span className="text-[10px] text-slate-500 break-all block mt-0.5" title={selectedEvent.source_file}>
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
        />
      )}
    </div>
  );
};
