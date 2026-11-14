import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { AgGridReact, CustomHeaderProps } from 'ag-grid-react';
import {
  RowSelectedEvent,
  RowClickedEvent,
  CellContextMenuEvent,
  IDatasource,
  IGetRowsParams,
  GridApi,
  ColDef,
} from 'ag-grid-community';
import {
  Table,
  LayoutGrid,
  Database,
  Filter,
  X,
  RotateCcw,
  RefreshCw,
  ArrowUp,
  ArrowDown,
  Image as ImageIcon,
} from 'lucide-react';
import { apiClient, ArtifactItem } from '../api/client';
import { ColumnFilterPopover } from './ColumnFilterPopover';
import { RowContextMenu } from './RowContextMenu';

export type ViewMode = 'column' | 'thumbnail';

interface ArtifactGridProps {
  caseId: string;
  selectedArtifact: ArtifactItem | null;
  onSelectRow: (row: Record<string, unknown> | null) => void;
  onInspectEntity?: (entityValue: string) => void;
  onQuickBookmark?: (row: Record<string, unknown>) => void;
  globalSearch?: string;
  externalKeywords?: string[];
  dateRange?: {
    preset: string;
    startUtc?: string;
    endUtc?: string;
  };
  tags?: string[];
}

// Infer best default view mode based on artifact category
function getSuggestedViewMode(artifact: ArtifactItem | null): ViewMode {
  if (!artifact) return 'column';
  const cat = artifact.category.toLowerCase();
  const name = (artifact.display_name + ' ' + artifact.table_name).toLowerCase();
  if (cat.includes('media') || name.includes('thumbcache') || name.includes('exif') || name.includes('ocr')) {
    return 'thumbnail';
  }
  return 'column';
}

// Helper to format human-readable column headers for forensic artifacts (especially Prefetch 8 runs)
export const formatColumnDisplayName = (colName: string): string => {
  const lower = colName.toLowerCase();
  switch (lower) {
    case 'lastrun':
      return 'Last Run (Run 1 of 8)';
    case 'previousrun0':
      return 'Previous Run 1 (Run 2 of 8)';
    case 'previousrun1':
      return 'Previous Run 2 (Run 3 of 8)';
    case 'previousrun2':
      return 'Previous Run 3 (Run 4 of 8)';
    case 'previousrun3':
      return 'Previous Run 4 (Run 5 of 8)';
    case 'previousrun4':
      return 'Previous Run 5 (Run 6 of 8)';
    case 'previousrun5':
      return 'Previous Run 6 (Run 7 of 8)';
    case 'previousrun6':
      return 'Previous Run 7 (Run 8 of 8)';
    case 'previousrun7':
      return 'Previous Run 8 (Run 8 of 8)';
    case 'previousrun8':
      return 'Previous Run 8 of 8';
    case 'runcount':
      return 'Total Run Count';
    default:
      return colName;
  }
};

// Custom AG Grid Header Component with Excel/WFT Multi-Select Checkbox Filter trigger
interface CustomHeaderWithFilterProps extends CustomHeaderProps {
  onTriggerFilter: (colName: string, event: React.MouseEvent) => void;
  hasActiveFilter: boolean;
  filterValuesCount: number;
}

const CustomHeaderComponent: React.FC<CustomHeaderWithFilterProps> = (props) => {
  const colName = props.column.getColId();
  const sortDirection = props.column.getSort();

  const handleSort = (event: React.MouseEvent) => {
    event.stopPropagation();
    props.progressSort(event.shiftKey);
  };

  const handleFilterClick = (event: React.MouseEvent) => {
    event.stopPropagation();
    props.onTriggerFilter(colName, event);
  };

  return (
    <div className="flex items-center justify-between w-full h-full select-none pr-1">
      {/* Column Name & Sort */}
      <div
        className="flex items-center gap-1.5 cursor-pointer truncate flex-1 min-w-0"
        onClick={handleSort}
        title={`Sort by ${props.displayName}`}
      >
        <span className="font-bold text-[11px] uppercase tracking-wider truncate text-slate-700 dark:text-slate-200">
          {props.displayName}
        </span>
        {sortDirection === 'asc' && <ArrowUp className="w-3 h-3 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />}
        {sortDirection === 'desc' && <ArrowDown className="w-3 h-3 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />}
      </div>

      {/* Multi-Select Checkbox Filter Trigger Button */}
      {colName !== '_row_id' && (
        <button
          onClick={handleFilterClick}
          className={`p-1 rounded transition-all shrink-0 ml-1 cursor-pointer ${
            props.hasActiveFilter
              ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0369a1] dark:text-[#38bdf8] font-bold border border-[#0284c7] shadow-2xs'
              : 'text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-200/60 dark:hover:bg-slate-800'
          }`}
          title={`Filter ${props.displayName}`}
        >
          <Filter className={`w-3 h-3 ${props.hasActiveFilter ? 'fill-[#0284c7] text-[#0284c7] dark:fill-[#38bdf8] dark:text-[#38bdf8]' : ''}`} />
        </button>
      )}
    </div>
  );
};

export const ArtifactGrid: React.FC<ArtifactGridProps> = ({
  caseId,
  selectedArtifact,
  onSelectRow,
  globalSearch = '',
  externalKeywords = [],
  dateRange,
  tags = [],
}) => {
  const [columns, setColumns] = useState<string[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [filteredCount, setFilteredCount] = useState<number>(0);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Multi-Select Column Filters: { [columnName]: selectedValues[] }
  const [columnFilters, setColumnFilters] = useState<Record<string, unknown[]>>({});

  // Active Filter Popover State
  const [activeFilterPopover, setActiveFilterPopover] = useState<{
    columnName: string;
    position: { top: number; left: number };
  } | null>(null);

  // View Mode: Column (AG Grid Single Page Virtualized), Thumbnail (Continuous Infinite Scroll)
  const [viewMode, setViewMode] = useState<ViewMode>('column');
  const [selectedRowId, setSelectedRowId] = useState<unknown>(null);

  // Thumbnail rows state for continuous scrolling
  const [thumbnailRows, setThumbnailRows] = useState<Record<string, unknown>[]>([]);
  const [isLoadingThumbnails, setIsLoadingThumbnails] = useState(false);

  // Right-Click Context Menu State
  const [contextMenu, setContextMenu] = useState<{
    position: { x: number; y: number };
    row: Record<string, any>;
    cellValue?: unknown;
  } | null>(null);

  const gridApiRef = useRef<GridApi | null>(null);
  const tableName = selectedArtifact?.table_name;

  // Suggested view mode and reset state when switching artifact tables
  useEffect(() => {
    if (selectedArtifact) {
      setViewMode(getSuggestedViewMode(selectedArtifact));
      setSelectedRowId(null);
      setColumnFilters({});
      setThumbnailRows([]);
    }
  }, [selectedArtifact?.table_name]);

  // Load initial table columns and counts whenever selectedArtifact changes
  useEffect(() => {
    let isCancelled = false;
    if (!caseId || !tableName) {
      setColumns([]);
      setTotalCount(0);
      setFilteredCount(0);
      return;
    }

    setIsLoading(true);
    setError(null);

    apiClient
      .getTableData(caseId, tableName, {
        limit: 1,
        offset: 0,
      })
      .then((meta) => {
        if (!isCancelled) {
          setColumns(meta.columns || []);
          setTotalCount(meta.total_count);
          setFilteredCount(meta.filtered_count);
          setIsLoading(false);
        }
      })
      .catch((err) => {
        if (!isCancelled) {
          setError(err instanceof Error ? err.message : String(err));
          setIsLoading(false);
        }
      });

    return () => {
      isCancelled = true;
    };
  }, [caseId, tableName]);

  // Handle Thumbnail Continuous Loading
  const fetchThumbnails = useCallback(
    async (reset: boolean = false) => {
      if (!caseId || !tableName) return;
      setIsLoadingThumbnails(true);
      try {
        const offset = reset ? 0 : thumbnailRows.length;
        let combinedSearch = globalSearch.trim();
        if (externalKeywords.length > 0) {
          combinedSearch = externalKeywords.join(' ');
        }

        const res = await apiClient.getTableData(caseId, tableName, {
          limit: 80,
          offset,
          search: combinedSearch || undefined,
          column_filters: Object.keys(columnFilters).length > 0 ? columnFilters : undefined,
          start_time: dateRange?.startUtc,
          end_time: dateRange?.endUtc,
          tags: tags.length > 0 ? tags : undefined,
        });

        if (reset) {
          setThumbnailRows(res.rows);
          if (res.rows.length > 0) {
            onSelectRow(res.rows[0]);
            setSelectedRowId(res.rows[0]._row_id);
          }
        } else {
          setThumbnailRows((prev) => [...prev, ...res.rows]);
        }
        setTotalCount(res.total_count);
        setFilteredCount(res.filtered_count);
      } catch (err) {
        console.error('[ArtifactGrid] Error fetching thumbnails:', err);
      } finally {
        setIsLoadingThumbnails(false);
      }
    },
    [caseId, tableName, globalSearch, externalKeywords, columnFilters, dateRange?.startUtc, dateRange?.endUtc, tags, thumbnailRows.length, onSelectRow]
  );

  // Trigger thumbnail reload when entering thumbnail mode or filters change
  useEffect(() => {
    if (viewMode === 'thumbnail') {
      fetchThumbnails(true);
    }
  }, [viewMode, tableName, globalSearch, externalKeywords, columnFilters, dateRange?.startUtc, dateRange?.endUtc, tags]);

  const handleThumbnailScroll = (e: React.UIEvent<HTMLDivElement>) => {
    const target = e.currentTarget;
    const threshold = 300;
    if (
      target.scrollHeight - target.scrollTop - target.clientHeight < threshold &&
      !isLoadingThumbnails &&
      thumbnailRows.length < filteredCount
    ) {
      fetchThumbnails(false);
    }
  };

  const handleTriggerFilter = useCallback((colName: string, event: React.MouseEvent) => {
    const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
    setActiveFilterPopover({
      columnName: colName,
      position: {
        top: rect.bottom + 6,
        left: Math.max(10, rect.left - 100),
      },
    });
  }, []);

  const handleApplyColumnFilter = useCallback((columnName: string, selectedValues: unknown[]) => {
    setColumnFilters((prev) => ({
      ...prev,
      [columnName]: selectedValues,
    }));
  }, []);

  const handleClearColumnFilter = useCallback((columnName: string) => {
    setColumnFilters((prev) => {
      const next = { ...prev };
      delete next[columnName];
      return next;
    });
  }, []);

  const handleClearAllColumnFilters = useCallback(() => {
    setColumnFilters({});
  }, []);

  // Construct AG Grid Single-Page Infinite Row Model Datasource
  // This virtualizes all 98,904+ rows into a single continuous scrollable grid with NO page buttons
  const datasource: IDatasource = useMemo(() => {
    if (!caseId || !tableName) {
      return {
        getRows: (params: IGetRowsParams) => params.successCallback([], 0),
      };
    }

    return {
      getRows: async (params: IGetRowsParams) => {
        try {
          const { startRow, endRow, sortModel } = params;
          const limit = Math.max(1, endRow - startRow);
          const offset = startRow;

          let sortCol = '_row_id';
          let sortDir: 'ASC' | 'DESC' = 'ASC';
          if (sortModel && sortModel.length > 0) {
            sortCol = sortModel[0].colId;
            sortDir = (sortModel[0].sort?.toUpperCase() === 'DESC' ? 'DESC' : 'ASC') as 'ASC' | 'DESC';
          }

          let combinedSearch = globalSearch.trim();
          if (externalKeywords.length > 0) {
            combinedSearch = externalKeywords.join(' ');
          }

          const res = await apiClient.getTableData(caseId, tableName, {
            limit,
            offset,
            sort_col: sortCol,
            sort_dir: sortDir,
            search: combinedSearch || undefined,
            column_filters: Object.keys(columnFilters).length > 0 ? columnFilters : undefined,
            start_time: dateRange?.startUtc,
            end_time: dateRange?.endUtc,
            tags: tags.length > 0 ? tags : undefined,
          });

          // Inform AG Grid of rows and exact filtered count for the virtual scrollbar
          params.successCallback(res.rows, res.filtered_count);

          // Update header count badges
          setTotalCount(res.total_count);
          setFilteredCount(res.filtered_count);

          // Auto-select row 0 on initial load
          if (startRow === 0 && res.rows.length > 0) {
            setSelectedRowId((prev: unknown) => {
              if (prev === null) {
                onSelectRow(res.rows[0]);
                return res.rows[0]._row_id;
              }
              return prev;
            });
          }
        } catch (err: unknown) {
          console.error('[ArtifactGrid] Error fetching virtual rows:', err);
          params.failCallback();
        }
      },
    };
  }, [
    caseId,
    tableName,
    globalSearch,
    externalKeywords,
    columnFilters,
    dateRange?.startUtc,
    dateRange?.endUtc,
    tags,
    onSelectRow,
  ]);

  // Synchronize datasource with gridApi whenever datasource changes
  useEffect(() => {
    if (gridApiRef.current) {
      gridApiRef.current.setGridOption('datasource', datasource);
    }
  }, [datasource]);

  // Handle Refresh button
  const handleRefresh = useCallback(() => {
    if (gridApiRef.current) {
      gridApiRef.current.purgeInfiniteCache();
    }
    if (viewMode === 'thumbnail') {
      fetchThumbnails(true);
    }
  }, [viewMode, fetchThumbnails]);

  // Build AG Grid Column Definitions
  const columnDefs = useMemo<ColDef[]>(() => {
    if (!columns || columns.length === 0) return [];

    return columns.map((colName) => {
      const isFilterActive = Boolean(columnFilters[colName] && columnFilters[colName].length > 0);
      const filterCount = columnFilters[colName]?.length || 0;

      const colLower = colName.toLowerCase();
      let defaultWidth = 180;
      let minColWidth = 120;
      if (colName === '_row_id') {
        defaultWidth = 90;
        minColWidth = 70;
      } else if (
        colLower.includes('path') ||
        colLower.includes('url') ||
        colLower.includes('command') ||
        colLower.includes('description') ||
        colLower.includes('payload') ||
        colLower.includes('summary') ||
        colLower.includes('message')
      ) {
        defaultWidth = 320;
        minColWidth = 180;
      } else if (colLower.includes('name') || colLower.includes('hash') || colLower.includes('title')) {
        defaultWidth = 240;
        minColWidth = 140;
      } else if (colLower.includes('run') && (colLower.includes('previous') || colLower.includes('last'))) {
        defaultWidth = 230;
        minColWidth = 160;
      } else if (colLower.includes('time') || colLower.includes('date')) {
        defaultWidth = 200;
        minColWidth = 150;
      } else if (colLower.includes('size') || colLower.includes('count') || colLower.includes('id')) {
        defaultWidth = 130;
        minColWidth = 90;
      }

      const displayName = formatColumnDisplayName(colName);

      return {
        field: colName,
        headerName: displayName,
        headerComponent: CustomHeaderComponent,
        headerComponentParams: {
          onTriggerFilter: handleTriggerFilter,
          hasActiveFilter: isFilterActive,
          filterValuesCount: filterCount,
        },
        sortable: true,
        resizable: true,
        filter: false,
        width: defaultWidth,
        minWidth: minColWidth,
        maxWidth: undefined,
        cellRenderer: (params: { value: unknown; data: unknown }) => {
          if (!params.data) {
            // Skeleton while loading block
            return <span className="text-slate-300 dark:text-slate-600 animate-pulse text-[11px] font-mono">...</span>;
          }
          const val = params.value;
          if (val === null || val === undefined) {
            return <span className="text-slate-400 italic text-[11px] font-mono">—</span>;
          }
          const strVal = String(val);

          return (
            <div className="flex items-center justify-between w-full max-w-full min-w-0 overflow-hidden text-xs font-mono">
              <span className="truncate pr-1 select-text min-w-0 flex-1" title={strVal}>
                {strVal}
              </span>
            </div>
          );
        },
      };
    });
  }, [columns, columnFilters, handleTriggerFilter]);

  const onRowSelected = useCallback(
    (event: RowSelectedEvent) => {
      if (event.node.isSelected() && event.data) {
        onSelectRow(event.data);
        setSelectedRowId(event.data._row_id);
      }
    },
    [onSelectRow]
  );

  const onRowClicked = useCallback(
    (event: RowClickedEvent) => {
      if (event.data) {
        onSelectRow(event.data);
        setSelectedRowId(event.data._row_id);
      }
    },
    [onSelectRow]
  );

  const onCellContextMenu = useCallback(
    (event: CellContextMenuEvent) => {
      if (event.data) {
        onSelectRow(event.data);
        setSelectedRowId(event.data._row_id);
        if (event.node) {
          event.node.setSelected(true);
        }
        const mouseEv = event.event as MouseEvent;
        if (mouseEv) {
          setContextMenu({
            position: { x: mouseEv.clientX, y: mouseEv.clientY },
            row: event.data,
            cellValue: event.value,
          });
        }
      }
    },
    [onSelectRow]
  );

  const handleExportGridCsv = useCallback(() => {
    if (gridApiRef.current) {
      gridApiRef.current.exportDataAsCsv({
        fileName: `${tableName || 'evidence'}_export.csv`,
      });
    } else if (tableName) {
      const csvUrl = apiClient.getTableExportCsvUrl(caseId, tableName);
      const a = document.createElement('a');
      a.href = csvUrl;
      a.download = `${tableName}_export.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
  }, [caseId, tableName]);

  const activeFiltersList = Object.entries(columnFilters);

  return (
    <div className="flex flex-col h-full bg-white dark:bg-[#1e293b] overflow-hidden font-sans border-r border-[#cbd5e1] dark:border-[#334155]">
      {/* Top Bar: EVIDENCE (<count>) on left, View Switcher & Refresh on right (NO pagination buttons!) */}
      <div className="h-12 px-4 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0 select-none">
        {/* Left: EVIDENCE (<count>) */}
        <div className="flex items-center gap-2.5 min-w-0">
          <Table className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />
          <span className="font-extrabold text-xs uppercase tracking-wide text-[#0f172a] dark:text-[#f8fafc] truncate">
            EVIDENCE{' '}
            <span className="font-mono text-[#0284c7] dark:text-[#38bdf8]">
              ({filteredCount.toLocaleString()}
              {filteredCount !== totalCount && ` of ${totalCount.toLocaleString()}`})
            </span>
          </span>

          {selectedArtifact && (
            <span className="text-[11px] font-sans px-2.5 py-0.5 rounded bg-white dark:bg-[#1e293b] text-slate-700 dark:text-slate-300 border border-[#cbd5e1] dark:border-[#334155] hidden sm:inline truncate font-semibold">
              {selectedArtifact.display_name}
            </span>
          )}
        </div>

        {/* Center / Right Controls: Column/Thumbnail View, Refresh */}
        <div className="flex items-center gap-3 shrink-0">
          {/* View Selector Dropdown */}
          <div className="flex items-center gap-1 bg-white dark:bg-[#1e293b] p-0.5 rounded border border-[#cbd5e1] dark:border-[#334155] shadow-2xs">
            <button
              onClick={() => setViewMode('column')}
              className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-semibold transition-colors cursor-pointer ${
                viewMode === 'column'
                  ? 'bg-[#0284c7] text-white border border-[#0369a1] shadow-2xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-[#0f172a] dark:hover:text-[#f8fafc]'
              }`}
              title="Column View (Single Continuous Virtualized Grid)"
            >
              <Table className="w-3.5 h-3.5" />
              <span>Column view</span>
            </button>

            <button
              onClick={() => setViewMode('thumbnail')}
              className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-semibold transition-colors cursor-pointer ${
                viewMode === 'thumbnail'
                  ? 'bg-[#0284c7] text-white border border-[#0369a1] shadow-2xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-[#0f172a] dark:hover:text-[#f8fafc]'
              }`}
              title="Thumbnail View (Continuous Infinite Scroll)"
            >
              <LayoutGrid className="w-3.5 h-3.5" />
              <span>Thumbnail</span>
            </button>
          </div>

          {/* Refresh Button */}
          <button
            onClick={handleRefresh}
            disabled={isLoading}
            className="p-1.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] text-slate-600 dark:text-slate-300 transition-colors cursor-pointer"
            title="Refresh Table Data"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-[#0284c7]' : ''}`} />
          </button>
        </div>
      </div>

      {/* Active Column Filters Pills Bar */}
      {activeFiltersList.length > 0 && (
        <div className="px-4 py-2 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between text-xs shrink-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-bold text-[#0284c7] dark:text-[#38bdf8] flex items-center gap-1 text-[11px] uppercase tracking-wide">
              <Filter className="w-3.5 h-3.5" />
              Active Filters:
            </span>
            {activeFiltersList.map(([colName, vals]) => (
              <span
                key={colName}
                className="flex items-center gap-1 px-2.5 py-0.5 rounded bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc] font-mono text-[11px] shadow-2xs"
              >
                <strong>{colName}:</strong> {vals.length} selected
                <button
                  onClick={() => handleClearColumnFilter(colName)}
                  className="p-0.5 hover:bg-slate-100 dark:hover:bg-slate-800 rounded text-slate-500 hover:text-slate-800 cursor-pointer"
                  title="Remove filter"
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}
          </div>

          <button
            onClick={handleClearAllColumnFilters}
            className="flex items-center gap-1 text-xs text-[#991b1b] dark:text-red-400 hover:underline font-semibold cursor-pointer"
          >
            <RotateCcw className="w-3 h-3" />
            <span>Reset Filters</span>
          </button>
        </div>
      )}

      {/* Main Grid View Area */}
      <div className="flex-1 overflow-hidden relative">
        {isLoading && columns.length === 0 && (
          <div className="absolute inset-0 bg-white/70 dark:bg-[#0f172a]/70 z-10 flex flex-col items-center justify-center gap-2">
            <div className="w-6 h-6 border-2 border-[#0284c7] border-t-transparent rounded-full animate-spin" />
            <span className="text-xs font-mono text-slate-600 dark:text-slate-400">
              Querying {tableName || 'evidence'}...
            </span>
          </div>
        )}

        {error && (
          <div className="p-8 text-center text-[#991b1b] dark:text-red-400">
            <p className="font-bold text-sm mb-1">Failed to query table data</p>
            <p className="font-mono text-xs">{error}</p>
          </div>
        )}

        {!selectedArtifact ? (
          <div className="flex flex-col items-center justify-center h-full text-slate-400 gap-3">
            <Database className="w-10 h-10 text-slate-300 dark:text-slate-600" />
            <p className="font-bold text-slate-600 dark:text-slate-400">No Artifact Table Selected</p>
            <p className="text-xs text-slate-400">
              Select an artifact category from the left sidebar to inspect evidence rows.
            </p>
          </div>
        ) : viewMode === 'column' ? (
          <div className="w-full h-full ag-theme-quartz">
            <AgGridReact
              rowModelType="infinite"
              datasource={datasource}
              cacheBlockSize={250}
              maxBlocksInCache={100}
              infiniteInitialRowCount={filteredCount > 0 ? filteredCount : 1}
              columnDefs={columnDefs}
              rowSelection="single"
              preventDefaultOnContextMenu={true}
              onCellContextMenu={onCellContextMenu}
              onRowSelected={onRowSelected}
              onRowClicked={onRowClicked}
              onGridReady={(event) => {
                gridApiRef.current = event.api;
                event.api.setGridOption('datasource', datasource);
              }}
              defaultColDef={{
                resizable: true,
                sortable: true,
                minWidth: 70,
                 autoHeaderHeight: true,
              }}
              rowHeight={38}
              headerHeight={40}
              animateRows={false}
              suppressCellFocus={true}
              enableCellTextSelection={true}
            />
          </div>
        ) : (
          // Thumbnail View for Media/Carved files with Continuous Infinite Scroll
          <div
            onScroll={handleThumbnailScroll}
            className="h-full overflow-y-auto p-4 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-4 bg-[#f1f5f9] dark:bg-[#0f172a]"
          >
            {thumbnailRows.length === 0 && !isLoadingThumbnails ? (
              <div className="col-span-full text-center py-12 text-slate-400 text-xs">No media records found.</div>
            ) : (
              thumbnailRows.map((row, idx) => {
                const isSelected = selectedRowId === row._row_id;
                const fileName = String(row.file_name || row.FileName || row.SourceFilename || `Record_${idx}`);
                const filePath = String(row.file_path || row.FullPath || row.Path || '');
                const ocrText = String(row.ocr_extracted_text || '');

                return (
                  <div
                    key={idx}
                    onClick={() => {
                      onSelectRow(row);
                      setSelectedRowId(row._row_id);
                    }}
                    onContextMenu={(e) => {
                      e.preventDefault();
                      onSelectRow(row);
                      setSelectedRowId(row._row_id);
                      setContextMenu({
                        position: { x: e.clientX, y: e.clientY },
                        row,
                        cellValue: row.file_name || row.FileName,
                      });
                    }}
                    className={`rounded border overflow-hidden transition-all cursor-pointer flex flex-col justify-between ${
                      isSelected
                        ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] border-[#0284c7] dark:border-[#38bdf8] text-[#0f172a] dark:text-[#f8fafc] shadow-xs'
                        : 'bg-white dark:bg-[#1e293b] border-[#cbd5e1] dark:border-[#334155] hover:border-slate-400 text-[#0f172a] dark:text-[#f8fafc] shadow-2xs'
                    }`}
                  >
                    <div className="h-32 bg-slate-100 dark:bg-[#0f172a] flex items-center justify-center relative overflow-hidden border-b border-[#cbd5e1] dark:border-[#334155]">
                      {Boolean(row.source_file || row.carved_file_path || row.carved_path) && (
                        <img
                          src={apiClient.getMediaStreamUrl(caseId, String(row.carved_file_path || row.carved_path || row.source_file))}
                          alt={fileName}
                          className="w-full h-full object-cover absolute inset-0 z-10"
                          onError={(e) => { (e.currentTarget as HTMLElement).style.display = 'none'; }}
                        />
                      )}
                      {Boolean(row.source_file || row.carved_file_path || row.carved_path || row.file_path) ? (
                        <img
                          src={`/api/cases/${caseId}/raw-file?path=${encodeURIComponent(String(row.carved_file_path || row.carved_path || row.source_file || row.file_path))}`}
                          alt={fileName}
                          className="w-full h-full object-cover"
                          onError={(e) => { (e.currentTarget as HTMLElement).style.display = 'none'; }}
                        />
                      ) : (
                        <ImageIcon className="w-10 h-10 text-slate-400 dark:text-slate-600" />
                      )}
                      {ocrText && (
                        <div className="absolute bottom-1 right-1 px-1.5 py-0.5 rounded bg-black/60 text-white font-mono text-[9px] uppercase">
                          OCR Text
                        </div>
                      )}
                    </div>
                    <div className="p-2.5">
                      <p className="font-bold text-xs truncate" title={fileName}>
                        {fileName}
                      </p>
                      <p className="text-[10px] text-slate-500 dark:text-slate-400 font-mono truncate" title={filePath}>
                        {filePath || `Row #${row._row_id}`}
                      </p>
                    </div>
                  </div>
                );
              })
            )}

            {isLoadingThumbnails && (
              <div className="col-span-full py-6 flex items-center justify-center gap-2 text-xs text-slate-500 font-mono">
                <RefreshCw className="w-4 h-4 animate-spin text-[#0284c7]" />
                <span>Loading more records in same page...</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Floating Column Filter Popover */}
      {activeFilterPopover && tableName && (
        <ColumnFilterPopover
          caseId={caseId}
          tableName={tableName}
          columnName={activeFilterPopover.columnName}
          currentFilterValues={columnFilters[activeFilterPopover.columnName]}
          onApplyFilter={handleApplyColumnFilter}
          onClearFilter={handleClearColumnFilter}
          onClose={() => setActiveFilterPopover(null)}
          position={activeFilterPopover.position}
        />
      )}

      {/* Native Magnet AXIOM-style Right-Click Forensic Context Menu */}
      {contextMenu && (
        <RowContextMenu
          caseId={caseId}
          position={contextMenu.position}
          onClose={() => setContextMenu(null)}
          row={contextMenu.row}
          tableName={tableName}
          cellValue={contextMenu.cellValue}
          onExportTableCsv={handleExportGridCsv}
        />
      )}
    </div>
  );
};
