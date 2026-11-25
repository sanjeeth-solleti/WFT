import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import {
  Database,
  Search,
  Download,
  RefreshCw,
  Globe,
  Mail,
  Phone,
  CreditCard,
  Link2,
  Cpu,
  FileText,
  BarChart3,
  ListFilter,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Copy,
  Check,
  Sparkles,
} from 'lucide-react';
import { apiClient, TableDataResponse } from '../api/client';
import { useResizable, ResizeHandle } from './ResizeHandle';

interface BulkExtractorWorkbenchProps {
  caseId: string;
  globalSearch?: string;
  onInspectEntity?: (entityValue: string) => void;
}

type BulkMode = 'features' | 'histograms';

const SCANNER_LABELS: Record<string, { label: string; color: string }> = {
  email: {
    label: 'Email Addresses',
    color: 'bg-sky-100 text-sky-800 dark:bg-sky-950/60 dark:text-sky-300 border-sky-300 dark:border-sky-800',
  },
  domain: {
    label: 'Domains & Hosts',
    color: 'bg-indigo-100 text-indigo-800 dark:bg-indigo-950/60 dark:text-indigo-300 border-indigo-300 dark:border-indigo-800',
  },
  email_domain: {
    label: 'Email Domains',
    color: 'bg-indigo-100 text-indigo-800 dark:bg-indigo-950/60 dark:text-indigo-300 border-indigo-300 dark:border-indigo-800',
  },
  url: {
    label: 'URLs & Web Links',
    color: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800',
  },
  url_services: {
    label: 'URL Services',
    color: 'bg-teal-100 text-teal-800 dark:bg-teal-950/60 dark:text-teal-300 border-teal-300 dark:border-teal-800',
  },
  url_searches: {
    label: 'Search Engine Queries',
    color: 'bg-cyan-100 text-cyan-800 dark:bg-cyan-950/60 dark:text-cyan-300 border-cyan-300 dark:border-cyan-800',
  },
  ip: {
    label: 'IPv4 / Network Endpoints',
    color: 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300 border-amber-300 dark:border-amber-800',
  },
  telephone: {
    label: 'Telephone Numbers',
    color: 'bg-purple-100 text-purple-800 dark:bg-purple-950/60 dark:text-purple-300 border-purple-300 dark:border-purple-800',
  },
  ccn: {
    label: 'Payment Card Numbers (CCN)',
    color: 'bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300 border-rose-300 dark:border-rose-800',
  },
  ccn_track2: {
    label: 'Magnetic Track 2 Data',
    color: 'bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300 border-rose-300 dark:border-rose-800',
  },
  winpe: {
    label: 'Windows PE Headers',
    color: 'bg-orange-100 text-orange-800 dark:bg-orange-950/60 dark:text-orange-300 border-orange-300 dark:border-orange-800',
  },
  winlnk: {
    label: 'Carved LNK Shortcuts',
    color: 'bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300 border-blue-300 dark:border-blue-800',
  },
  winprefetch: {
    label: 'Carved Prefetch Artifacts',
    color: 'bg-violet-100 text-violet-800 dark:bg-violet-950/60 dark:text-violet-300 border-violet-300 dark:border-violet-800',
  },
};

function getScannerIcon(scanner: string) {
  const sc = (scanner || '').toLowerCase();
  if (sc.includes('email')) return <Mail className="w-3.5 h-3.5 text-sky-500 shrink-0" />;
  if (sc.includes('domain') || sc === 'ip') return <Globe className="w-3.5 h-3.5 text-indigo-500 shrink-0" />;
  if (sc.includes('url')) return <Link2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />;
  if (sc.includes('telephone')) return <Phone className="w-3.5 h-3.5 text-purple-500 shrink-0" />;
  if (sc.includes('ccn')) return <CreditCard className="w-3.5 h-3.5 text-rose-500 shrink-0" />;
  if (sc.includes('win')) return <Cpu className="w-3.5 h-3.5 text-amber-500 shrink-0" />;
  return <FileText className="w-3.5 h-3.5 text-slate-400 shrink-0" />;
}

export const BulkExtractorWorkbench: React.FC<BulkExtractorWorkbenchProps> = ({
  caseId,
  globalSearch = '',
  onInspectEntity,
}) => {
  const [mode, setMode] = useState<BulkMode>('features');
  const [featuresResp, setFeaturesResp] = useState<TableDataResponse | null>(null);
  const [histogramsResp, setHistogramsResp] = useState<TableDataResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [selectedScanner, setSelectedScanner] = useState<string>('ALL');
  const [localSearch, setLocalSearch] = useState('');
  const [page, setPage] = useState(0);
  const [pageSize] = useState(200);
  const [selectedRow, setSelectedRow] = useState<Record<string, any> | null>(null);
  const [copiedFeature, setCopiedFeature] = useState(false);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const leftPanel = useResizable({
    storageKey: 'wft_bulk_extractor_left_w',
    initialWidth: 260,
    minWidth: 190,
    maxWidth: 480,
    direction: 'left',
    containerRef,
  });

  const activeTableName =
    mode === 'features'
      ? 'parsed_bulk_extractor_features'
      : 'parsed_bulk_extractor_histograms';

  const effectiveSearch = useMemo(() => {
    const parts = [globalSearch.trim(), localSearch.trim()].filter(Boolean);
    return parts.join(' ');
  }, [globalSearch, localSearch]);

  const fetchData = useCallback(async () => {
    if (!caseId) return;
    setIsLoading(true);
    setError(null);
    try {
      const colFilters: Record<string, unknown[]> = {};
      if (selectedScanner !== 'ALL') {
        colFilters.scanner = [selectedScanner];
      }
      const [featRes, histRes] = await Promise.all([
        apiClient
          .getTableData(caseId, 'parsed_bulk_extractor_features', {
            limit: mode === 'features' ? pageSize : 500,
            offset: mode === 'features' ? page * pageSize : 0,
            search: mode === 'features' && effectiveSearch ? effectiveSearch : undefined,
            column_filters: mode === 'features' && selectedScanner !== 'ALL' ? colFilters : undefined,
          })
          .catch((): TableDataResponse => ({
            case_id: caseId,
            table_name: 'parsed_bulk_extractor_features',
            total_count: 0,
            filtered_count: 0,
            limit: pageSize,
            offset: 0,
            columns: [],
            rows: [],
          })),
        apiClient
          .getTableData(caseId, 'parsed_bulk_extractor_histograms', {
            limit: mode === 'histograms' ? pageSize : 500,
            offset: mode === 'histograms' ? page * pageSize : 0,
            search: mode === 'histograms' && effectiveSearch ? effectiveSearch : undefined,
            column_filters: mode === 'histograms' && selectedScanner !== 'ALL' ? colFilters : undefined,
            sort_col: 'count',
            sort_dir: 'DESC',
          })
          .catch((): TableDataResponse => ({
            case_id: caseId,
            table_name: 'parsed_bulk_extractor_histograms',
            total_count: 0,
            filtered_count: 0,
            limit: pageSize,
            offset: 0,
            columns: [],
            rows: [],
          })),
      ]);
      setFeaturesResp(featRes);
      setHistogramsResp(histRes);
    } catch (err: any) {
      setError(err?.message || 'Failed to load Bulk Extractor output');
    } finally {
      setIsLoading(false);
    }
  }, [caseId, mode, page, pageSize, effectiveSearch, selectedScanner]);

  useEffect(() => {
    setPage(0);
    setSelectedRow(null);
  }, [caseId, mode, selectedScanner, effectiveSearch]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const activeResp = mode === 'features' ? featuresResp : histogramsResp;
  const rows = activeResp?.rows || [];
  const totalCount = activeResp?.total_count || 0;
  const totalFeaturesCount = featuresResp?.total_count || 0;
  const totalHistogramsCount = histogramsResp?.total_count || 0;

  // Compute scanner list from available rows
  const scannerBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    const sampleRows =
      (mode === 'features' ? featuresResp?.rows : histogramsResp?.rows) || [];
    for (const r of sampleRows) {
      const sc = String(r.scanner || r.feature_type || 'unknown').toLowerCase();
      counts[sc] = (counts[sc] || 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [mode, featuresResp?.rows, histogramsResp?.rows]);

  const handleExportCsv = () => {
    if (!caseId) return;
    const url = apiClient.getTableExportCsvUrl(
      caseId,
      activeTableName,
      effectiveSearch || undefined
    );
    const a = document.createElement('a');
    a.href = url;
    a.download = `${caseId}_${activeTableName}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handleCopyFeature = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedFeature(true);
      window.setTimeout(() => setCopiedFeature(false), 1500);
    } catch {
      // ignore
    }
  };

  const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));

  return (
    <div
      ref={containerRef}
      data-testid="bulk-extractor-workbench"
      className="flex-1 flex h-full overflow-hidden bg-[#f1f5f9] dark:bg-[#0f172a] text-[#0f172a] dark:text-[#f8fafc] font-sans select-none"
    >
      {/* Left Scanner Sidebar */}
      <aside
        style={{ width: `${leftPanel.width}px` }}
        className="bg-white dark:bg-[#1e293b] border-r border-[#cbd5e1] dark:border-[#334155] flex flex-col h-full shrink-0"
      >
        <div className="p-3 border-b border-[#cbd5e1] dark:border-[#334155] space-y-2.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
              <span className="text-xs font-bold uppercase tracking-wider">Bulk Extractor</span>
            </div>
            <button
              type="button"
              onClick={fetchData}
              className="p-1 rounded hover:bg-slate-100 dark:hover:bg-[#334155] text-slate-500 hover:text-[#0f172a] dark:hover:text-white cursor-pointer"
              title="Refresh Bulk Extractor tables"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-[#0284c7]' : ''}`} />
            </button>
          </div>

          {/* Mode Toggle: Features vs Histograms */}
          <div className="grid grid-cols-2 gap-1 p-1 rounded bg-[#f1f5f9] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155]">
            <button
              type="button"
              data-testid="be-tab-features"
              onClick={() => setMode('features')}
              className={`px-2 py-1.5 rounded text-[11px] font-bold flex items-center justify-center gap-1 transition-colors cursor-pointer ${
                mode === 'features'
                  ? 'bg-[#0284c7] text-white shadow-2xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-[#0f172a] dark:hover:text-white'
              }`}
            >
              <Database className="w-3 h-3" />
              <span>Features ({totalFeaturesCount.toLocaleString()})</span>
            </button>
            <button
              type="button"
              data-testid="be-tab-histograms"
              onClick={() => setMode('histograms')}
              className={`px-2 py-1.5 rounded text-[11px] font-bold flex items-center justify-center gap-1 transition-colors cursor-pointer ${
                mode === 'histograms'
                  ? 'bg-[#0284c7] text-white shadow-2xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-[#0f172a] dark:hover:text-white'
              }`}
            >
              <BarChart3 className="w-3 h-3" />
              <span>Histograms ({totalHistogramsCount.toLocaleString()})</span>
            </button>
          </div>
        </div>

        {/* Scanner Filter List */}
        <div className="px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500 border-b border-[#e2e8f0] dark:border-[#334155] flex items-center justify-between">
          <span>Feature Scanners</span>
          <ListFilter className="w-3 h-3" />
        </div>
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          <button
            type="button"
            onClick={() => setSelectedScanner('ALL')}
            className={`w-full flex items-center justify-between px-2.5 py-2 rounded text-xs transition-colors cursor-pointer border ${
              selectedScanner === 'ALL'
                ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0f172a] dark:text-[#f8fafc] font-bold border-[#0284c7] dark:border-[#38bdf8]'
                : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-[#334155] border-transparent'
            }`}
          >
            <span className="truncate">All Scanners</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155]">
              {totalCount.toLocaleString()}
            </span>
          </button>

          {scannerBreakdown.map(([sc, cnt]) => {
            const meta = SCANNER_LABELS[sc];
            const isSelected = selectedScanner === sc;
            return (
              <button
                key={sc}
                type="button"
                onClick={() => setSelectedScanner(isSelected ? 'ALL' : sc)}
                className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs transition-colors cursor-pointer border ${
                  isSelected
                    ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0f172a] dark:text-[#f8fafc] font-bold border-[#0284c7] dark:border-[#38bdf8]'
                    : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-[#334155] border-transparent'
                }`}
              >
                <div className="flex items-center gap-2 min-w-0 pr-1">
                  {getScannerIcon(sc)}
                  <div className="flex flex-col text-left min-w-0">
                    <span className="truncate font-mono text-[11px] font-semibold">{sc}</span>
                    {meta && (
                      <span className="text-[10px] text-slate-500 dark:text-slate-400 truncate">
                        {meta.label}
                      </span>
                    )}
                  </div>
                </div>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] shrink-0">
                  {cnt.toLocaleString()}
                </span>
              </button>
            );
          })}
        </div>
      </aside>

      <ResizeHandle
        orientation="vertical"
        onMouseDown={leftPanel.handleMouseDown}
        onDoubleClick={leftPanel.resetWidth}
        isDragging={leftPanel.isDragging}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col h-full min-w-0 overflow-hidden">
        {/* Toolbar */}
        <div className="h-12 bg-white dark:bg-[#1e293b] border-b border-[#cbd5e1] dark:border-[#334155] px-4 flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-xs font-bold text-[#0f172a] dark:text-[#f8fafc] truncate">
              {mode === 'features'
                ? 'Bulk Extractor Carved Features & Contexts'
                : 'Bulk Extractor Aggregated Feature Histograms'}
            </span>
            {selectedScanner !== 'ALL' && (
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0284c7] dark:text-[#38bdf8] border border-[#0284c7]/40">
                scanner: {selectedScanner}
              </span>
            )}
            <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
              ({totalCount.toLocaleString()} records)
            </span>
          </div>

          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
              <input
                type="text"
                value={localSearch}
                onChange={(e) => setLocalSearch(e.target.value)}
                placeholder="Filter features, offsets, contexts..."
                className="w-64 pl-8 pr-3 py-1 bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded text-xs font-mono text-[#0f172a] dark:text-[#f8fafc] focus:outline-none focus:border-[#0284c7]"
              />
            </div>

            <button
              type="button"
              onClick={handleExportCsv}
              className="flex items-center gap-1.5 px-2.5 py-1 bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] rounded text-xs font-semibold text-slate-700 dark:text-slate-200 cursor-pointer"
              title="Export current Bulk Extractor table to CSV"
            >
              <Download className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        {/* Table & Inspector Split */}
        <div className="flex-1 flex overflow-hidden min-h-0">
          <div className="flex-1 flex flex-col overflow-hidden min-w-0">
            <div className="flex-1 overflow-auto bg-white dark:bg-[#1e293b]">
              {error ? (
                <div className="p-8 text-center text-xs text-rose-600 dark:text-rose-400 font-mono">
                  {error}
                </div>
              ) : rows.length === 0 ? (
                <div className="p-12 text-center space-y-2">
                  <div className="text-sm font-bold text-slate-600 dark:text-slate-300">
                    {isLoading
                      ? 'Loading Bulk Extractor records...'
                      : 'No Bulk Extractor output records found for this filter'}
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto">
                    Enable Bulk Extractor in Process Evidence (Step 3: Recovery, Carving & Bulk Extractor) to scan disk images or folders for carved URLs, emails, domains, IPs, telephones, and headers.
                  </p>
                </div>
              ) : mode === 'features' ? (
                <table className="w-full text-left text-xs border-collapse select-text">
                  <thead className="sticky top-0 bg-[#f8fafc] dark:bg-[#0f172a] text-[11px] font-mono uppercase text-slate-500 dark:text-slate-400 border-b border-[#cbd5e1] dark:border-[#334155] select-none">
                    <tr>
                      <th className="py-2 px-3 w-16">#</th>
                      <th className="py-2 px-3 w-36">Scanner</th>
                      <th className="py-2 px-3 w-40">Byte Offset</th>
                      <th className="py-2 px-3">Extracted Feature / IOC</th>
                      <th className="py-2 px-3">Flanking Context</th>
                      <th className="py-2 px-3 w-36">Source File</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#e2e8f0] dark:divide-[#334155] font-mono">
                    {rows.map((r: Record<string, any>, idx: number) => {
                      const rowId = Number(r._row_id ?? idx + 1 + page * pageSize);
                      const sc = String(r.scanner || r.feature_type || '');
                      const feat = String(r.feature || r.feature_value || '');
                      const ctx = String(r.context || '');
                      const offset = String(r.offset_str || r.byte_offset || '');
                      const src = String(r.source_file || '');
                      const isSel = selectedRow === r;
                      const badge = SCANNER_LABELS[sc.toLowerCase()];

                      return (
                        <tr
                          key={`${rowId}-${idx}`}
                          onClick={() => setSelectedRow(r)}
                          className={`cursor-pointer transition-colors ${
                            isSel
                              ? 'bg-[#bae6fd]/60 dark:bg-[#0c4a6e]/60'
                              : 'hover:bg-slate-50 dark:hover:bg-[#334155]/40'
                          }`}
                        >
                          <td className="py-1.5 px-3 text-slate-400">{rowId}</td>
                          <td className="py-1.5 px-3">
                            <span
                              className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                                badge?.color ||
                                'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border-slate-300 dark:border-slate-700'
                              }`}
                            >
                              {sc}
                            </span>
                          </td>
                          <td className="py-1.5 px-3 text-slate-600 dark:text-slate-400 truncate max-w-[160px]" title={offset}>
                            {offset}
                          </td>
                          <td className="py-1.5 px-3 font-semibold text-[#0f172a] dark:text-[#f8fafc] break-all max-w-md">
                            <div className="flex items-center justify-between gap-2">
                              <span className="truncate" title={feat}>
                                {feat}
                              </span>
                              {onInspectEntity && feat && (
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    onInspectEntity(feat);
                                  }}
                                  className="text-[10px] text-[#0284c7] dark:text-[#38bdf8] hover:underline shrink-0 flex items-center gap-0.5 cursor-pointer"
                                  title="Pivot in Entity Connections Drawer"
                                >
                                  <ExternalLink className="w-3 h-3" />
                                </button>
                              )}
                            </div>
                          </td>
                          <td className="py-1.5 px-3 text-slate-600 dark:text-slate-300 truncate max-w-md" title={ctx}>
                            {ctx}
                          </td>
                          <td className="py-1.5 px-3 text-slate-500 truncate max-w-[140px]" title={src}>
                            {src}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <table className="w-full text-left text-xs border-collapse select-text">
                  <thead className="sticky top-0 bg-[#f8fafc] dark:bg-[#0f172a] text-[11px] font-mono uppercase text-slate-500 dark:text-slate-400 border-b border-[#cbd5e1] dark:border-[#334155] select-none">
                    <tr>
                      <th className="py-2 px-3 w-16">#</th>
                      <th className="py-2 px-3 w-40">Scanner</th>
                      <th className="py-2 px-3 w-32 text-right">Hit Count</th>
                      <th className="py-2 px-3">Aggregated Feature / IOC</th>
                      <th className="py-2 px-3 w-44">Histogram File</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#e2e8f0] dark:divide-[#334155] font-mono">
                    {rows.map((r: Record<string, any>, idx: number) => {
                      const rowId = Number(r._row_id ?? idx + 1 + page * pageSize);
                      const sc = String(r.scanner || '');
                      const cnt = Number(r.count ?? r.frequency ?? 0);
                      const feat = String(r.feature || r.key || '');
                      const src = String(r.source_file || '');
                      const isSel = selectedRow === r;
                      const badge = SCANNER_LABELS[sc.toLowerCase()];

                      return (
                        <tr
                          key={`${rowId}-${idx}`}
                          onClick={() => setSelectedRow(r)}
                          className={`cursor-pointer transition-colors ${
                            isSel
                              ? 'bg-[#bae6fd]/60 dark:bg-[#0c4a6e]/60'
                              : 'hover:bg-slate-50 dark:hover:bg-[#334155]/40'
                          }`}
                        >
                          <td className="py-1.5 px-3 text-slate-400">{rowId}</td>
                          <td className="py-1.5 px-3">
                            <span
                              className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                                badge?.color ||
                                'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border-slate-300 dark:border-slate-700'
                              }`}
                            >
                              {sc}
                            </span>
                          </td>
                          <td className="py-1.5 px-3 text-right font-bold text-[#0284c7] dark:text-[#38bdf8]">
                            {cnt.toLocaleString()}
                          </td>
                          <td className="py-1.5 px-3 font-semibold text-[#0f172a] dark:text-[#f8fafc] break-all">
                            <div className="flex items-center justify-between gap-2">
                              <span className="truncate" title={feat}>
                                {feat}
                              </span>
                              {onInspectEntity && feat && (
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    onInspectEntity(feat);
                                  }}
                                  className="text-[10px] text-[#0284c7] dark:text-[#38bdf8] hover:underline shrink-0 flex items-center gap-0.5 cursor-pointer"
                                  title="Pivot in Entity Connections Drawer"
                                >
                                  <ExternalLink className="w-3 h-3" />
                                </button>
                              )}
                            </div>
                          </td>
                          <td className="py-1.5 px-3 text-slate-500 truncate" title={src}>
                            {src}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>

            {/* Pagination Footer */}
            <div className="h-9 bg-[#f8fafc] dark:bg-[#0f172a] border-t border-[#cbd5e1] dark:border-[#334155] px-4 flex items-center justify-between text-xs font-mono text-slate-500 shrink-0">
              <span>
                Showing {rows.length > 0 ? page * pageSize + 1 : 0}–
                {Math.min(totalCount, page * pageSize + rows.length)} of {totalCount.toLocaleString()}
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  disabled={page <= 0}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  className="p-1 rounded border border-[#cbd5e1] dark:border-[#334155] disabled:opacity-40 hover:bg-white dark:hover:bg-[#1e293b] cursor-pointer"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                </button>
                <span>
                  Page {page + 1} / {totalPages}
                </span>
                <button
                  type="button"
                  disabled={page + 1 >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                  className="p-1 rounded border border-[#cbd5e1] dark:border-[#334155] disabled:opacity-40 hover:bg-white dark:hover:bg-[#1e293b] cursor-pointer"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>

          {/* Right Context Detail Inspector */}
          {selectedRow && (
            <div className="w-80 bg-white dark:bg-[#1e293b] border-l border-[#cbd5e1] dark:border-[#334155] p-4 flex flex-col gap-3 overflow-y-auto shrink-0 select-text">
              <div className="flex items-center justify-between pb-2 border-b border-[#cbd5e1] dark:border-[#334155]">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-200">
                  Feature Inspector
                </span>
                <button
                  type="button"
                  onClick={() =>
                    handleCopyFeature(String(selectedRow.feature || selectedRow.feature_value || ''))
                  }
                  className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-100 dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] text-[11px] font-mono cursor-pointer"
                >
                  {copiedFeature ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-500" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>

              <div className="space-y-2 text-xs font-mono">
                <div>
                  <span className="text-[10px] uppercase text-slate-400 block">Scanner</span>
                  <span className="font-bold text-[#0284c7] dark:text-[#38bdf8]">
                    {String(selectedRow.scanner || selectedRow.feature_type || '')}
                  </span>
                </div>

                {selectedRow.offset_str && (
                  <div>
                    <span className="text-[10px] uppercase text-slate-400 block">Forensic Offset / Path</span>
                    <span className="break-all text-slate-700 dark:text-slate-300">
                      {String(selectedRow.offset_str)}
                    </span>
                  </div>
                )}

                {selectedRow.count !== undefined && (
                  <div>
                    <span className="text-[10px] uppercase text-slate-400 block">Occurrences</span>
                    <span className="font-bold text-slate-800 dark:text-slate-100">
                      {Number(selectedRow.count).toLocaleString()}
                    </span>
                  </div>
                )}

                <div>
                  <span className="text-[10px] uppercase text-slate-400 block">Extracted Feature</span>
                  <div className="mt-1 p-2 rounded bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] break-all font-semibold">
                    {String(selectedRow.feature || selectedRow.feature_value || '')}
                  </div>
                </div>

                {selectedRow.context && (
                  <div>
                    <span className="text-[10px] uppercase text-slate-400 block">Flanking Context Window</span>
                    <div className="mt-1 p-2 rounded bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] break-all whitespace-pre-wrap text-[11px]">
                      {String(selectedRow.context)}
                    </div>
                  </div>
                )}

                {selectedRow.source_file && (
                  <div>
                    <span className="text-[10px] uppercase text-slate-400 block">Source Output File</span>
                    <span className="text-slate-600 dark:text-slate-400">
                      {String(selectedRow.source_file)}
                    </span>
                  </div>
                )}

                {onInspectEntity && (selectedRow.feature || selectedRow.feature_value) && (
                  <button
                    type="button"
                    onClick={() =>
                      onInspectEntity(String(selectedRow.feature || selectedRow.feature_value))
                    }
                    className="w-full mt-2 py-1.5 px-3 rounded bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-sans font-semibold flex items-center justify-center gap-1.5 cursor-pointer"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    <span>Pivot Entity Connections</span>
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
