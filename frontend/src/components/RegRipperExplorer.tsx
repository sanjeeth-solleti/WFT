import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import {
  Cpu,
  Search,
  Copy,
  Check,
  RotateCcw,
  Shield,
  Layers,
  HardDrive,
  FileText,
  ExternalLink,
  ChevronRight,
  Filter,
  Loader2,
  Terminal,
  Activity,
  AlertTriangle,
  FolderOpen,
  Hash,
  Download,
} from 'lucide-react';
import { apiClient, RegRipperPluginItem, RegRipperPluginDetail } from '../api/client';
import { useResizable, ResizeHandle } from './ResizeHandle';
import { RowContextMenu } from './RowContextMenu';

interface RegRipperExplorerProps {
  caseId: string;
  onInspectEntity?: (entityValue: string) => void;
  selectedPluginName?: string | null;
  onSelectPlugin?: (pluginName: string | null) => void;
}

// Regex to detect linkable entities inside report text
const ENTITY_REGEX = /([A-Za-z]:\\[\w\s\-.\\]+\.(?:exe|dll|sys|bat|ps1|vbs|txt|pdf|docx|dat|hve)|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\bS-1-5-[0-9\-]+\b|\b[a-fA-F0-9]{32,64}\b)/g;

function getHiveColor(hiveType: string): string {
  const h = (hiveType || '').toUpperCase();
  if (h.includes('SYSTEM')) return 'bg-sky-100 text-sky-800 border-sky-300 dark:bg-sky-950/60 dark:text-sky-300 dark:border-sky-800';
  if (h.includes('SOFTWARE')) return 'bg-purple-100 text-purple-800 border-purple-300 dark:bg-purple-950/60 dark:text-purple-300 dark:border-purple-800';
  if (h.includes('SAM')) return 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800';
  if (h.includes('SECURITY')) return 'bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-800';
  if (h.includes('NTUSER')) return 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800';
  if (h.includes('USRCLASS')) return 'bg-indigo-100 text-indigo-800 border-indigo-300 dark:bg-indigo-950/60 dark:text-indigo-300 dark:border-indigo-800';
  if (h.includes('AMCACHE')) return 'bg-teal-100 text-teal-800 border-teal-300 dark:bg-teal-950/60 dark:text-teal-300 dark:border-teal-800';
  return 'bg-slate-100 text-slate-800 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700';
}

export const RegRipperExplorer: React.FC<RegRipperExplorerProps> = ({
  caseId,
  onInspectEntity,
  selectedPluginName,
  onSelectPlugin,
}) => {
  const [plugins, setPlugins] = useState<RegRipperPluginItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Active selected plugin
  const [selectedPlugin, setSelectedPlugin] = useState<RegRipperPluginItem | null>(null);
  const [pluginDetail, setPluginDetail] = useState<RegRipperPluginDetail | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState<boolean>(false);

  // Filter state
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [hiveFilter, setHiveFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  // Search within report text
  const [reportSearch, setReportSearch] = useState<string>('');
  const [isCopied, setIsCopied] = useState<boolean>(false);
  const [isReRunning, setIsReRunning] = useState<boolean>(false);

  // Right-Click Context Menu State
  const [contextMenu, setContextMenu] = useState<{
    position: { x: number; y: number };
    row: Record<string, any>;
    cellValue?: unknown;
  } | null>(null);

  // Resizable Left Plugins Sidebar
  const containerRef = useRef<HTMLDivElement>(null);
  const leftPane = useResizable({
    initialWidth: 384,
    minWidth: 260,
    maxWidth: 700,
    storageKey: 'wft_regripper_left_width',
    direction: 'left',
    containerRef,
    minCenterWidth: 320,
  });

  // Fetch all plugins
  const loadPlugins = useCallback(async (preferredPluginName?: string | null) => {
    if (!caseId) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await apiClient.getRegRipperPlugins(caseId);
      const list = res.plugins || [];
      setPlugins(list);

      if (list.length > 0) {
        let match = list[0];
        if (preferredPluginName) {
          const found = list.find(
            (p) => p.plugin_name.toLowerCase() === preferredPluginName.toLowerCase()
          );
          if (found) match = found;
        }
        setSelectedPlugin(match);
      } else {
        setSelectedPlugin(null);
        setPluginDetail(null);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    loadPlugins(selectedPluginName);
  }, [loadPlugins, selectedPluginName]);

  // When selectedPlugin changes, fetch detail report
  useEffect(() => {
    if (!caseId || !selectedPlugin) {
      setPluginDetail(null);
      return;
    }
    setIsLoadingDetail(true);
    apiClient
      .getRegRipperPluginDetail(caseId, selectedPlugin.plugin_name, selectedPlugin.hive_name)
      .then((detail) => {
        setPluginDetail(detail);
      })
      .catch((err) => {
        console.error('Error fetching plugin detail:', err);
        setPluginDetail(null);
      })
      .finally(() => {
        setIsLoadingDetail(false);
      });
  }, [caseId, selectedPlugin]);

  // Synchronize when selectedPluginName prop changes from outside (e.g. dropdown)
  useEffect(() => {
    if (selectedPluginName && plugins.length > 0) {
      const match = plugins.find(
        (p) => p.plugin_name.toLowerCase() === selectedPluginName.toLowerCase()
      );
      if (match && match._row_id !== selectedPlugin?._row_id) {
        setSelectedPlugin(match);
      }
    }
  }, [selectedPluginName, plugins, selectedPlugin?._row_id]);

  // Trigger on-demand RegRipper run
  const handleTriggerRun = async () => {
    if (!caseId || isReRunning) return;
    setIsReRunning(true);
    try {
      await apiClient.runRegRipper(caseId);
      await loadPlugins(selectedPlugin?.plugin_name);
    } catch (err) {
      console.error('Error running RegRipper:', err);
    } finally {
      setIsReRunning(false);
    }
  };

  // Filtered plugins list
  const filteredPlugins = useMemo(() => {
    return plugins.filter((p) => {
      // Hive filter
      if (hiveFilter !== 'ALL') {
        const h = p.hive_type.toUpperCase();
        if (!h.includes(hiveFilter)) return false;
      }
      // Category filter
      if (categoryFilter !== 'ALL') {
        if (!p.category.toLowerCase().includes(categoryFilter.toLowerCase())) return false;
      }
      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          p.plugin_name.toLowerCase().includes(q) ||
          p.description.toLowerCase().includes(q) ||
          p.category.toLowerCase().includes(q) ||
          p.mitre_attack.toLowerCase().includes(q) ||
          p.hive_name.toLowerCase().includes(q) ||
          p.summary_line.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [plugins, hiveFilter, categoryFilter, searchQuery]);

  // Extract distinct hive types and categories for filter chips
  const distinctHives = useMemo(() => {
    const s = new Set<string>();
    plugins.forEach((p) => {
      if (p.hive_type) s.add(p.hive_type.toUpperCase());
    });
    return Array.from(s).sort();
  }, [plugins]);

  const distinctCategories = useMemo(() => {
    const s = new Set<string>();
    plugins.forEach((p) => {
      if (p.category && p.category !== 'Registry & OS') s.add(p.category);
    });
    return Array.from(s).sort();
  }, [plugins]);

  // Copy report to clipboard
  const handleCopyReport = () => {
    if (!pluginDetail?.report_text) return;
    navigator.clipboard.writeText(pluginDetail.report_text);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  // Render report line with clickable entity highlight
  const renderReportLine = (line: string, lineIndex: number) => {
    // If user is searching inside report, highlight matches
    if (reportSearch.trim()) {
      const q = reportSearch.trim();
      const parts = line.split(new RegExp(`(${q.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')})`, 'gi'));
      return (
        <span key={lineIndex}>
          {parts.map((part, i) =>
            part.toLowerCase() === q.toLowerCase() ? (
              <mark key={i} className="bg-amber-300 dark:bg-amber-600/80 text-black dark:text-white px-0.5 rounded">
                {part}
              </mark>
            ) : (
              renderEntityText(part, `${lineIndex}-${i}`)
            )
          )}
        </span>
      );
    }
    return renderEntityText(line, lineIndex);
  };

  const renderEntityText = (text: string, keyPrefix: string | number) => {
    const parts: React.ReactNode[] = [];
    let lastIndex = 0;
    let match: RegExpExecArray | null;

    ENTITY_REGEX.lastIndex = 0;
    while ((match = ENTITY_REGEX.exec(text)) !== null) {
      if (match.index > lastIndex) {
        parts.push(text.substring(lastIndex, match.index));
      }
      const val = match[0];
      parts.push(
        <button
          key={`${keyPrefix}-${match.index}`}
          onClick={(e) => {
            e.stopPropagation();
            onInspectEntity?.(val);
          }}
          className="text-[#0284c7] dark:text-[#38bdf8] hover:underline font-bold inline-block cursor-pointer"
          title={`Inspect entity "${val}" in Connections Entity Graph`}
        >
          {val}
        </button>
      );
      lastIndex = ENTITY_REGEX.lastIndex;
    }
    if (lastIndex < text.length) {
      parts.push(text.substring(lastIndex));
    }
    return <span key={keyPrefix}>{parts}</span>;
  };

  return (
    <div
      ref={containerRef}
      className="flex-1 flex overflow-hidden w-full h-full bg-[#f1f5f9] dark:bg-[#0f172a] text-[#0f172a] dark:text-[#f8fafc] font-sans relative"
    >
      {/* LEFT PANE: PLUGINS LIST & FILTERS (Resizable) */}
      <aside
        style={{ width: `${leftPane.width}px` }}
        className="bg-white dark:bg-[#1e293b] border-r border-[#cbd5e1] dark:border-[#334155] flex flex-col h-full shrink-0 shadow-xs overflow-hidden"
      >
        {/* Header toolbar */}
        <div className="p-3 border-b border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a] flex flex-col gap-2 shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded bg-sky-100 dark:bg-sky-950/60 border border-sky-300 dark:border-sky-800 text-[#0284c7] dark:text-[#38bdf8]">
                <Cpu className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-xs font-bold uppercase tracking-wider text-[#0f172a] dark:text-[#f8fafc]">
                  RegRipper Plugins
                </h2>
                <span className="text-[10px] text-slate-500 font-mono">
                  {plugins.length} plugins parsed
                </span>
              </div>
            </div>

            <button
              onClick={handleTriggerRun}
              disabled={isReRunning}
              className="flex items-center gap-1 px-2.5 py-1 bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] rounded text-xs font-semibold shadow-2xs text-[#0f172a] dark:text-[#f8fafc] cursor-pointer disabled:opacity-50 transition-colors"
              title="Re-run RegRipper 4.0 analysis on all registry hives"
            >
              <RotateCcw className={`w-3 h-3 text-[#0284c7] ${isReRunning ? 'animate-spin' : ''}`} />
              <span>{isReRunning ? 'Running...' : 'Re-run'}</span>
            </button>
          </div>

          {/* Search plugins input */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-400 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search plugins, categories, MITRE IDs..."
              className="w-full bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded pl-8 pr-2 py-1.5 text-xs text-[#0f172a] dark:text-[#f8fafc] placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-[#0284c7] shadow-2xs"
            />
          </div>

          {/* Quick Hive Filter Chips */}
          <div className="flex items-center gap-1 overflow-x-auto pb-0.5 scrollbar-none text-[11px]">
            <button
              onClick={() => setHiveFilter('ALL')}
              className={`px-2 py-0.5 rounded font-medium border cursor-pointer shrink-0 transition-colors ${
                hiveFilter === 'ALL'
                  ? 'bg-[#0284c7] text-white border-[#0284c7]'
                  : 'bg-white dark:bg-[#0f172a] text-slate-600 dark:text-slate-300 border-[#cbd5e1] dark:border-[#334155] hover:bg-slate-100'
              }`}
            >
              All Hives
            </button>
            {distinctHives.map((h) => (
              <button
                key={h}
                onClick={() => setHiveFilter(h)}
                className={`px-2 py-0.5 rounded font-mono uppercase font-medium border cursor-pointer shrink-0 transition-colors ${
                  hiveFilter === h
                    ? 'bg-[#0284c7] text-white border-[#0284c7]'
                    : 'bg-white dark:bg-[#0f172a] text-slate-600 dark:text-slate-300 border-[#cbd5e1] dark:border-[#334155] hover:bg-slate-100'
                }`}
              >
                {h}
              </button>
            ))}
          </div>

          {/* Quick Category Filter Chips */}
          {distinctCategories.length > 0 && (
            <div className="flex items-center gap-1 overflow-x-auto pb-0.5 scrollbar-none text-[10px]">
              <button
                onClick={() => setCategoryFilter('ALL')}
                className={`px-1.5 py-0.5 rounded font-medium border cursor-pointer shrink-0 transition-colors ${
                  categoryFilter === 'ALL'
                    ? 'bg-slate-800 text-white dark:bg-slate-200 dark:text-slate-900 border-transparent font-bold'
                    : 'bg-white dark:bg-[#0f172a] text-slate-500 border-[#cbd5e1] dark:border-[#334155] hover:bg-slate-100'
                }`}
              >
                All Categories
              </button>
              {distinctCategories.map((c) => (
                <button
                  key={c}
                  onClick={() => setCategoryFilter(c)}
                  className={`px-1.5 py-0.5 rounded capitalize font-medium border cursor-pointer shrink-0 transition-colors ${
                    categoryFilter === c
                      ? 'bg-slate-800 text-white dark:bg-slate-200 dark:text-slate-900 border-transparent font-bold'
                      : 'bg-white dark:bg-[#0f172a] text-slate-500 border-[#cbd5e1] dark:border-[#334155] hover:bg-slate-100'
                  }`}
                >
                  {c}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Plugins List */}
        <div className="flex-1 overflow-y-auto divide-y divide-[#cbd5e1]/40 dark:divide-[#334155]/40 select-none">
          {isLoading ? (
            <div className="py-12 flex flex-col items-center justify-center text-slate-500 gap-2">
              <Loader2 className="w-5 h-5 animate-spin text-[#0284c7]" />
              <span className="text-xs">Loading RegRipper plugins...</span>
            </div>
          ) : filteredPlugins.length === 0 ? (
            <div className="py-12 px-4 text-center text-slate-500 text-xs">
              <AlertTriangle className="w-6 h-6 mx-auto mb-2 text-amber-500" />
              <p className="font-semibold">No plugins match current filters.</p>
              <button
                onClick={() => {
                  setSearchQuery('');
                  setHiveFilter('ALL');
                  setCategoryFilter('ALL');
                }}
                className="mt-2 text-[#0284c7] hover:underline font-bold text-xs cursor-pointer"
              >
                Reset filters
              </button>
            </div>
          ) : (
            filteredPlugins.map((plugin) => {
              const isSelected = selectedPlugin?._row_id === plugin._row_id;
              const hiveBadgeClass = getHiveColor(plugin.hive_type);

              return (
                <div
                  key={`${plugin.hive_name}-${plugin.plugin_name}-${plugin._row_id}`}
                  onClick={() => {
                    setSelectedPlugin(plugin);
                    if (onSelectPlugin) {
                      onSelectPlugin(plugin.plugin_name);
                    }
                  }}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    setSelectedPlugin(plugin);
                    if (onSelectPlugin) {
                      onSelectPlugin(plugin.plugin_name);
                    }
                    setContextMenu({
                      position: { x: e.clientX, y: e.clientY },
                      row: {
                        ...plugin,
                        file_path: plugin.hive_name,
                      },
                      cellValue: plugin.plugin_name,
                    });
                  }}
                  className={`p-3 cursor-pointer transition-all flex flex-col gap-1 ${
                    isSelected
                      ? 'bg-sky-50 dark:bg-sky-950/40 border-l-4 border-l-[#0284c7]'
                      : 'hover:bg-slate-50 dark:hover:bg-[#334155]/40'
                  }`}
                >
                  <div className="flex items-center justify-between gap-1">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span className="font-bold text-xs text-[#0f172a] dark:text-[#f8fafc] truncate">
                        {plugin.plugin_name}
                      </span>
                      {plugin.plugin_version && (
                        <span className="text-[10px] text-slate-400 font-mono">
                          v.{plugin.plugin_version}
                        </span>
                      )}
                    </div>
                    <span className={`text-[9.5px] font-mono px-1.5 py-0.2 rounded font-bold border shrink-0 ${hiveBadgeClass}`}>
                      {plugin.hive_type}
                    </span>
                  </div>

                  {/* Summary preview */}
                  <p className="text-[11px] text-slate-600 dark:text-slate-300 line-clamp-2 leading-relaxed">
                    {plugin.summary_line || plugin.description}
                  </p>

                  <div className="flex items-center justify-between text-[10px] text-slate-400 pt-0.5">
                    <div className="flex items-center gap-1.5 truncate">
                      {plugin.mitre_attack && (
                        <span className="px-1.5 py-0.2 rounded bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 font-mono font-bold border border-rose-200 dark:border-rose-900">
                          {plugin.mitre_attack}
                        </span>
                      )}
                      <span className="capitalize truncate text-slate-500 font-medium">
                        {plugin.category}
                      </span>
                    </div>
                    <span className="font-mono text-slate-400 shrink-0">
                      {plugin.output_lines_count} lines
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </aside>

      {/* DRAGGABLE VERTICAL SPLITTER (Between Left Plugins List and Right Report Viewer) */}
      <ResizeHandle
        orientation="vertical"
        onMouseDown={leftPane.handleMouseDown}
        onDoubleClick={leftPane.resetWidth}
        isDragging={leftPane.isDragging}
        title="Drag to resize RegRipper Plugins sidebar (double-click to reset)"
      />

      {/* RIGHT MAIN PANE: PLUGIN REPORT VIEWER (flex-1) */}
      <section className="flex-1 flex flex-col h-full overflow-hidden bg-white dark:bg-[#0f172a] min-w-0">
        {selectedPlugin ? (
          <>
            {/* Report Header Bar */}
            <div className="p-4 border-b border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#1e293b] flex flex-col gap-3 shrink-0">
              <div className="flex items-start justify-between gap-4">
                <div className="flex flex-col gap-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h1 className="text-base font-bold text-[#0f172a] dark:text-[#f8fafc] tracking-tight">
                      {selectedPlugin.plugin_name}
                    </h1>
                    {selectedPlugin.plugin_version && (
                      <span className="text-xs text-slate-500 font-mono">
                        v.{selectedPlugin.plugin_version}
                      </span>
                    )}
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${getHiveColor(selectedPlugin.hive_type)}`}>
                      {selectedPlugin.hive_name} ({selectedPlugin.hive_type})
                    </span>
                    {selectedPlugin.mitre_attack && (
                      <span className="text-[10px] px-2 py-0.5 rounded bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 font-mono font-bold border border-rose-200 dark:border-rose-900">
                        MITRE: {selectedPlugin.mitre_attack}
                      </span>
                    )}
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-[#cbd5e1] dark:border-slate-700 font-medium capitalize">
                      {selectedPlugin.category}
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-300">
                    {selectedPlugin.description}
                  </p>
                </div>

                {/* Header Action Buttons */}
                <div className="flex items-center gap-2 shrink-0">
                  {/* Search inside report */}
                  <div className="relative w-48">
                    <Search className="w-3 h-3 absolute left-2.5 top-2.5 text-slate-400" />
                    <input
                      type="text"
                      value={reportSearch}
                      onChange={(e) => setReportSearch(e.target.value)}
                      placeholder="Find in report..."
                      className="w-full bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded pl-7 pr-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-[#0284c7]"
                    />
                  </div>

                  <button
                    onClick={handleCopyReport}
                    className="flex items-center gap-1 px-3 py-1 bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] rounded text-xs font-semibold shadow-2xs text-[#0f172a] dark:text-[#f8fafc] cursor-pointer transition-colors"
                    title="Copy complete report text to clipboard"
                  >
                    {isCopied ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                        <span className="text-emerald-600">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-slate-500" />
                        <span>Copy Output</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>

            {/* Main Report Monospace Card with Line Numbers */}
            <div className="flex-1 overflow-y-auto p-4 bg-[#f8fafc] dark:bg-[#0f172a]">
              {isLoadingDetail ? (
                <div className="h-64 flex flex-col items-center justify-center text-slate-500 gap-2">
                  <Loader2 className="w-6 h-6 animate-spin text-[#0284c7]" />
                  <span className="text-xs">Loading {selectedPlugin.plugin_name} report...</span>
                </div>
              ) : !pluginDetail?.report_text ? (
                <div className="p-8 text-center text-slate-500 text-xs">
                  <AlertTriangle className="w-6 h-6 mx-auto mb-2 text-amber-500" />
                  <p>No report text available for this plugin.</p>
                </div>
              ) : (
                <div className="border border-[#cbd5e1] dark:border-[#334155] rounded-md bg-white dark:bg-[#1e293b] shadow-2xs overflow-hidden">
                  <div className="px-3 py-1.5 border-b border-[#cbd5e1] dark:border-[#334155] bg-slate-50 dark:bg-[#0f172a] flex items-center justify-between text-[11px] text-slate-500">
                    <span className="font-mono">
                      Report: {selectedPlugin.plugin_name}.pl &bull; Hive: {selectedPlugin.hive_name}
                    </span>
                    <span className="font-mono">
                      {pluginDetail.report_text.split(/\r?\n/).length} lines
                    </span>
                  </div>

                  <div className="p-4 font-mono text-xs leading-relaxed overflow-x-auto whitespace-pre select-text">
                    {pluginDetail.report_text.split(/\r?\n/).map((line: string, idx: number) => (
                      <div key={idx} className="flex hover:bg-slate-50 dark:hover:bg-[#334155]/20 px-1 py-0.2 rounded">
                        <span className="w-10 shrink-0 text-slate-400 select-none text-right pr-3 font-mono text-[11px]">
                          {idx + 1}
                        </span>
                        <span className="text-[#0f172a] dark:text-[#f8fafc] flex-1">
                          {renderReportLine(line, idx)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-slate-400 gap-3">
            <Cpu className="w-12 h-12 text-slate-300 dark:text-slate-600" />
            <div className="text-center">
              <h3 className="font-bold text-sm text-[#0f172a] dark:text-[#f8fafc]">
                No RegRipper Plugin Selected
              </h3>
              <p className="text-xs text-slate-500 mt-1 max-w-sm">
                Choose a plugin from the left sidebar or from the RegRipper dropdown in the top header to examine parsed Windows Registry analysis.
              </p>
            </div>
          </div>
        )}
      </section>

      {/* Native Magnet AXIOM-style Right-Click Forensic Context Menu */}
      {contextMenu && (
        <RowContextMenu
          caseId={caseId}
          position={contextMenu.position}
          onClose={() => setContextMenu(null)}
          row={contextMenu.row}
          tableName="raw_regripper"
          cellValue={contextMenu.cellValue}
        />
      )}
    </div>
  );
};
