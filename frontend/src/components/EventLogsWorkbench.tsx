import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import {
  Activity,
  Shield,
  Search,
  Filter,
  FileText,
  Terminal,
  RefreshCw,
  ChevronRight,
  ChevronLeft,
  ChevronDown,
  Layers,
  HardDrive,
  Copy,
  Check,
  AlertTriangle,
  Lock,
  Cpu,
  User,
  Radio,
  FileCode,
  ExternalLink,
  Plus,
  X,
  Save,
  FileJson,
} from 'lucide-react';
import {
  apiClient,
  EvtxProfile,
  EvtxFileItem,
  EvtxProfilesResponse,
  EvtxRowsResponse,
} from '../api/client';
import { useResizable, ResizeHandle } from './ResizeHandle';
import { RowContextMenu } from './RowContextMenu';

interface EventLogsWorkbenchProps {
  caseId: string;
}

export const EventLogsWorkbench: React.FC<EventLogsWorkbenchProps> = ({ caseId }) => {
  // Profiles and files list
  const [profilesData, setProfilesData] = useState<EvtxProfilesResponse | null>(null);
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>('auth_logons');
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);
  const [isLoadingProfiles, setIsLoadingProfiles] = useState(false);

  // Table rows and state
  const [rowsData, setRowsData] = useState<EvtxRowsResponse | null>(null);
  const [selectedRow, setSelectedRow] = useState<Record<string, any> | null>(null);
  const [isLoadingRows, setIsLoadingRows] = useState(false);
  const [search, setSearch] = useState('');
  const [levelFilter, setLevelFilter] = useState('');
  const [eventRows, setEventRows] = useState<Record<string, any>[]>([]);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const pageSize = 250;

  // Search filter for files list
  const [fileSearch, setFileSearch] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Right-Click Context Menu State
  const [contextMenu, setContextMenu] = useState<{
    position: { x: number; y: number };
    row: Record<string, any>;
    cellValue?: unknown;
  } | null>(null);

  // Horizontal resizable pane widths (in pixels, persisted in localStorage)
  const containerRef = useRef<HTMLDivElement>(null);
  const leftPane = useResizable({
    initialWidth: 320,
    minWidth: 220,
    maxWidth: 600,
    storageKey: 'wft_eventlogs_left_width',
    direction: 'left',
    containerRef,
    minCenterWidth: 300,
  });
  const rightPane = useResizable({
    initialWidth: 380,
    minWidth: 260,
    maxWidth: 750,
    storageKey: 'wft_eventlogs_right_width',
    direction: 'right',
    containerRef,
    otherWidth: leftPane.width,
    minCenterWidth: 300,
  });
  const leftWidth = leftPane.width;
  const rightWidth = rightPane.width;

  // Raw Profile Editor Modal State
  const [isRawModalOpen, setIsRawModalOpen] = useState(false);
  const [rawEditorContent, setRawEditorContent] = useState('');
  const [rawFileName, setRawFileName] = useState('event_profiles.json');
  const [rawFilePath, setRawFilePath] = useState('rules/event_profiles.json');
  const [isSavingRaw, setIsSavingRaw] = useState(false);
  const [rawSaveError, setRawSaveError] = useState<string | null>(null);
  const [rawSaveSuccess, setRawSaveSuccess] = useState(false);

  // Create Custom Profile Modal State
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createDescription, setCreateDescription] = useState('');
  const [createEventIds, setCreateEventIds] = useState('');
  const [createChannels, setCreateChannels] = useState('');
  const [createKeywords, setCreateKeywords] = useState('');
  const [isCreatingProfile, setIsCreatingProfile] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Fetch profiles and file counts
  const fetchProfiles = useCallback(async () => {
    setIsLoadingProfiles(true);
    try {
      const data = await apiClient.getEvtxProfiles(caseId);
      setProfilesData(data);
    } catch (err) {
      console.error('Failed to load EVTX profiles:', err);
    } finally {
      setIsLoadingProfiles(false);
    }
  }, [caseId]);

  // Fetch rows based on selected profile, file, or filters
  const fetchRows = useCallback(async (reset: boolean = true) => {
    if (reset) {
      setIsLoadingRows(true);
    } else {
      setIsLoadingMore(true);
    }
    try {
      const offset = reset ? 0 : eventRows.length;
      const res = await apiClient.getEvtxRows(caseId, {
        profile_id: selectedProfileId || undefined,
        file_name: selectedFileName || undefined,
        level: levelFilter || undefined,
        search: search.trim() || undefined,
        limit: pageSize,
        offset,
        sort_col: 'TimeCreated',
        sort_dir: 'DESC',
      });
      setRowsData(res);
      if (reset) {
        setEventRows(res.rows || []);
        if (res.rows.length > 0) {
          setSelectedRow(res.rows[0]);
        } else {
          setSelectedRow(null);
        }
      } else {
        setEventRows((prev) => [...prev, ...(res.rows || [])]);
      }
    } catch (err) {
      console.error('Failed to fetch EVTX rows:', err);
    } finally {
      setIsLoadingRows(false);
      setIsLoadingMore(false);
    }
  }, [caseId, selectedProfileId, selectedFileName, levelFilter, search, eventRows.length]);

  useEffect(() => {
    fetchProfiles();
  }, [fetchProfiles]);

  useEffect(() => {
    fetchRows(true);
  }, [caseId, selectedProfileId, selectedFileName, levelFilter, search]);

  const handleSelectProfile = (pId: string) => {
    setSelectedProfileId(pId);
    setSelectedFileName(null);
    setSelectedRow(null);
  };

  const handleSelectFile = (fName: string | null) => {
    setSelectedFileName(fName);
    setSelectedProfileId(null);
    setSelectedRow(null);
  };

  const handleCopy = (text: string, keyName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(keyName);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Open Raw Profile Editor
  const handleOpenRawEditor = async () => {
    setRawSaveError(null);
    setRawSaveSuccess(false);
    try {
      const data = await apiClient.getEventProfiles(caseId);
      setRawFileName(data.profile_file_name || 'event_profiles.json');
      setRawFilePath(data.profile_file_path || 'rules/event_profiles.json');
      setRawEditorContent(data.raw_content || JSON.stringify(data.profiles, null, 2));
      setIsRawModalOpen(true);
    } catch (err: any) {
      alert(`Failed to load event profiles file: ${err.message || 'Unknown error'}`);
    }
  };

  // Save Raw Profiles Content
  const handleSaveRaw = async () => {
    setIsSavingRaw(true);
    setRawSaveError(null);
    try {
      // Validate JSON syntax locally first
      JSON.parse(rawEditorContent);
      const res = await apiClient.saveEventProfilesRaw(rawEditorContent);
      setRawSaveSuccess(true);
      await fetchProfiles();
      await fetchRows();
      setTimeout(() => {
        setRawSaveSuccess(false);
        setIsRawModalOpen(false);
      }, 1200);
    } catch (err: any) {
      setRawSaveError(err.message || 'Invalid JSON syntax');
    } finally {
      setIsSavingRaw(false);
    }
  };

  // Handle Create Custom Profile Submission
  const handleCreateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!createName.trim()) {
      setCreateError('Profile Name is required.');
      return;
    }
    setIsCreatingProfile(true);
    setCreateError(null);
    try {
      const eventIdsList = createEventIds
        .split(',')
        .map((id) => id.trim())
        .filter(Boolean)
        .map((id) => (isNaN(Number(id)) ? id : Number(id)));

      const channelsList = createChannels
        .split(',')
        .map((c) => c.trim())
        .filter(Boolean);

      const keywordsList = createKeywords
        .split(',')
        .map((k) => k.trim())
        .filter(Boolean);

      const res = await apiClient.createEventProfile({
        name: createName.trim(),
        description: createDescription.trim(),
        event_ids: eventIdsList,
        channels: channelsList,
        keywords: keywordsList,
      });

      // Reset form
      setCreateName('');
      setCreateDescription('');
      setCreateEventIds('');
      setCreateChannels('');
      setCreateKeywords('');
      setIsCreateModalOpen(false);

      // Refresh profiles list and select the newly created profile
      await fetchProfiles();
      if (res.profile?.id) {
        handleSelectProfile(res.profile.id);
      }
    } catch (err: any) {
      setCreateError(err.message || 'Failed to create profile');
    } finally {
      setIsCreatingProfile(false);
    }
  };

  const filteredFiles = useMemo(() => {
    if (!profilesData?.files) return [];
    if (!fileSearch.trim()) return profilesData.files;
    const q = fileSearch.toLowerCase();
    return profilesData.files.filter(
      (f) =>
        f.display_name.toLowerCase().includes(q) ||
        f.channel.toLowerCase().includes(q) ||
        f.file_name.toLowerCase().includes(q)
    );
  }, [profilesData?.files, fileSearch]);

  const totalPages = rowsData ? Math.ceil(rowsData.filtered_count / pageSize) : 0;
  const rows = eventRows;

  return (
    <div
      ref={containerRef}
      className="flex h-full w-full overflow-hidden bg-white dark:bg-[#1e293b] font-sans"
    >
      {/* ------------------------------------------------------------- */}
      {/* LEFT SIDEBAR: Forensic Profiles & Individual EVTX Files        */}
      {/* ------------------------------------------------------------- */}
      <aside
        style={{ width: `${leftWidth}px` }}
        className="bg-white dark:bg-[#1e293b] flex flex-col h-full select-none shrink-0 overflow-hidden"
      >
        {/* Sidebar Header */}
        <div className="p-3.5 border-b border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a] shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#0f172a] dark:text-[#f8fafc]">
              <Activity className="w-4 h-4 text-amber-500" />
              <span>EVENT LOG DFIR PROFILES</span>
            </div>
            <button
              onClick={fetchProfiles}
              disabled={isLoadingProfiles}
              className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors cursor-pointer"
              title="Refresh EVTX profiles and file counts"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoadingProfiles ? 'animate-spin text-[#0284c7]' : ''}`} />
            </button>
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
            Total Event Logs:{' '}
            <span className="font-mono font-bold text-amber-600 dark:text-amber-400">
              {profilesData?.total_evtx_count.toLocaleString() ?? '...'}
            </span>
          </p>
        </div>

        {/* Sidebar Scrollable Content */}
        <div className="flex-1 overflow-y-auto divide-y divide-[#cbd5e1] dark:divide-[#334155]">
          {/* SECTION 1: FORENSIC EVENT PROFILES */}
          <div className="p-2 space-y-1">
            <div className="px-2 py-1 flex items-center justify-between">
              <span className="text-[10px] font-extrabold uppercase tracking-wider text-slate-400">
                FORENSIC EVENT PROFILES
              </span>
              <button
                type="button"
                onClick={() => setIsCreateModalOpen(true)}
                className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#0284c7] hover:bg-[#0369a1] text-white flex items-center gap-1 cursor-pointer transition-colors shadow-2xs"
                title="Define new forensic hunting profile in rules/event_profiles.json"
              >
                <Plus className="w-3 h-3" />
                <span>+ Create Custom Profile</span>
              </button>
            </div>

            {profilesData?.profiles.map((p) => {
              const isSelected = selectedProfileId === p.id;
              return (
                <button
                  key={p.id}
                  onClick={() => handleSelectProfile(p.id)}
                  className={`w-full text-left px-2.5 py-2 rounded text-xs transition-colors flex items-center justify-between gap-2 cursor-pointer ${
                    isSelected
                      ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0369a1] dark:text-[#38bdf8] font-bold border border-[#0284c7] shadow-2xs'
                      : 'hover:bg-slate-100 dark:hover:bg-[#0f172a] text-[#0f172a] dark:text-[#f8fafc]'
                  }`}
                >
                  <div className="truncate flex-1 min-w-0">
                    <div className="truncate font-semibold">{p.name}</div>
                    <div className="text-[10px] text-slate-400 truncate font-normal mt-0.5">
                      {p.description}
                    </div>
                  </div>
                  <span
                    className={`font-mono text-[11px] font-bold px-2 py-0.5 rounded-full shrink-0 ${
                      p.hit_count > 0
                        ? 'bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-400'
                    }`}
                  >
                    {p.hit_count.toLocaleString()}
                  </span>
                </button>
              );
            })}
          </div>

          {/* SECTION 2: INDIVIDUAL .EVTX FILES */}
          <div className="p-2 space-y-1">
            <div className="px-2 py-1 flex items-center justify-between">
              <span className="text-[10px] font-extrabold uppercase tracking-wider text-slate-400">
                INDIVIDUAL LOG FILES (.EVTX)
              </span>
              <span className="font-mono text-[10px] text-slate-400">
                {profilesData?.files.length ?? 0} files
              </span>
            </div>

            {/* File Search Filter */}
            <div className="px-1 py-1">
              <div className="relative">
                <Search className="w-3 h-3 absolute left-2 top-2 text-slate-400 pointer-events-none" />
                <input
                  type="text"
                  value={fileSearch}
                  onChange={(e) => setFileSearch(e.target.value)}
                  placeholder="Filter log files..."
                  className="w-full text-xs pl-7 pr-2 py-1 rounded bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] focus:outline-none focus:border-[#0284c7] text-[#0f172a] dark:text-[#f8fafc]"
                />
              </div>
            </div>

            {/* All Logs (Combined) Button */}
            <button
              onClick={() => handleSelectFile(null)}
              className={`w-full text-left px-2.5 py-1.5 rounded text-xs transition-colors flex items-center justify-between cursor-pointer ${
                selectedFileName === null && selectedProfileId === null
                  ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0369a1] dark:text-[#38bdf8] font-bold border border-[#0284c7]'
                  : 'hover:bg-slate-100 dark:hover:bg-[#0f172a] text-[#0f172a] dark:text-[#f8fafc]'
              }`}
            >
              <span className="font-semibold">All Event Logs (Combined)</span>
              <span className="font-mono text-[10px] text-slate-400">
                {profilesData?.total_evtx_count.toLocaleString()}
              </span>
            </button>

            {/* Individual Files */}
            <div className="space-y-0.5 max-h-56 overflow-y-auto pr-1">
              {filteredFiles.map((file) => {
                const isSelected = selectedFileName === file.file_name;
                return (
                  <button
                    key={file.source_file}
                    onClick={() => handleSelectFile(file.file_name)}
                    className={`w-full text-left px-2 py-1 rounded text-xs transition-colors flex items-center justify-between gap-1.5 cursor-pointer ${
                      isSelected
                        ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0369a1] dark:text-[#38bdf8] font-bold border border-[#0284c7]'
                        : 'hover:bg-slate-100 dark:hover:bg-[#0f172a] text-[#0f172a] dark:text-[#f8fafc]'
                    }`}
                    title={file.source_file}
                  >
                    <span className="truncate text-[11px]">{file.display_name}</span>
                    <span className="font-mono text-[10px] text-slate-400 shrink-0">
                      {file.row_count.toLocaleString()}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* SECTION: ACTIVE PROFILE FILE */}
        <div className="p-3 border-t border-[#cbd5e1] dark:border-[#334155] space-y-1.5 shrink-0 bg-[#f8fafc] dark:bg-[#0f172a]">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
              ACTIVE PROFILE FILE
            </span>
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 font-bold">
              ACTIVE
            </span>
          </div>
          <button
            type="button"
            onClick={handleOpenRawEditor}
            className="w-full flex items-center justify-between text-xs text-slate-700 dark:text-slate-200 font-mono px-2.5 py-1.5 rounded bg-white dark:bg-[#1e293b] hover:bg-slate-100 dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] transition-colors cursor-pointer group"
            title="Click to view & edit raw rules/event_profiles.json"
          >
            <div className="flex items-center gap-2 truncate">
              <FileCode className="w-3.5 h-3.5 text-amber-500 shrink-0 group-hover:text-[#0284c7]" />
              <span className="truncate font-semibold">{rawFileName}</span>
            </div>
            <span className="text-[10px] text-slate-400 group-hover:text-[#0284c7]">Edit JSON</span>
          </button>
        </div>
      </aside>

      {/* DRAGGABLE VERTICAL SPLITTER 1 (Between Left Sidebar and Center Table) */}
      <ResizeHandle
        orientation="vertical"
        onMouseDown={leftPane.handleMouseDown}
        onDoubleClick={leftPane.resetWidth}
        isDragging={leftPane.isDragging}
        title="Drag to resize Profiles Sidebar (double-click to reset)"
      />

      {/* ------------------------------------------------------------- */}
      {/* CENTER & RIGHT: Grid + Full Payload / Details Split Pane       */}
      {/* ------------------------------------------------------------- */}
      <main className="flex-1 flex flex-col min-w-0 h-full overflow-hidden">
        {/* Top Filter & Search Toolbar */}
        <div className="h-12 px-4 bg-[#f8fafc] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-2 flex-1 max-w-md">
            <div className="relative w-full">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-400 pointer-events-none" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search across Payload, Provider, Message, Computer, User..."
                className="w-full text-xs pl-8 pr-3 py-1.5 rounded bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] focus:outline-none focus:border-[#0284c7] text-[#0f172a] dark:text-[#f8fafc]"
              />
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {/* Level Filter */}
            <select
              value={levelFilter}
              onChange={(e) => setLevelFilter(e.target.value)}
              className="text-xs px-2 py-1 rounded bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc] focus:outline-none"
            >
              <option value="">All Levels</option>
              <option value="Critical">Critical</option>
              <option value="Error">Error</option>
              <option value="Warning">Warning</option>
              <option value="Info">Information</option>
            </select>

            {/* Continuous View Badge & Refresh (NO page buttons!) */}
            {rowsData && rowsData.filtered_count > 0 && (
              <span className="hidden sm:inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-[11px] font-mono text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                <span>All {rowsData.filtered_count.toLocaleString()} hits in single view</span>
              </span>
            )}

            <button
              onClick={() => fetchRows(true)}
              disabled={isLoadingRows}
              className="p-1.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] text-slate-600 dark:text-slate-300 transition-colors cursor-pointer"
              title="Refresh EVTX data"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoadingRows ? 'animate-spin text-[#0284c7]' : ''}`} />
            </button>
          </div>
        </div>

        {/* Content Split: Center Table Grid + Draggable Splitter + Right Details/XML Pane */}
        <div className="flex-1 flex overflow-hidden">
          {/* Virtualized/Continuous Events Table */}
          <div
            onScroll={(e) => {
              const t = e.currentTarget;
              if (
                t.scrollHeight - t.scrollTop - t.clientHeight < 300 &&
                !isLoadingRows &&
                !isLoadingMore &&
                rowsData &&
                eventRows.length < rowsData.filtered_count
              ) {
                fetchRows(false);
              }
            }}
            className="flex-1 overflow-auto"
          >
            {isLoadingRows ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-400 gap-2">
                <RefreshCw className="w-6 h-6 animate-spin text-[#0284c7]" />
                <span className="text-xs font-mono">Querying event records from DuckDB...</span>
              </div>
            ) : rows.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-400">
                <p className="text-xs">No matching EVTX records found.</p>
              </div>
            ) : (
              <>
                <table className="w-full text-left text-xs border-collapse">
                <thead className="sticky top-0 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] z-10 text-[11px] font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider select-none">
                  <tr>
                    <th className="px-3 py-2 w-16">EID</th>
                    <th className="px-3 py-2 w-40">Time (UTC)</th>
                    <th className="px-3 py-2 w-20">Level</th>
                    <th className="px-3 py-2 w-36">Channel</th>
                    <th className="px-3 py-2 w-32">Computer</th>
                    <th className="px-3 py-2 w-32">User</th>
                    <th className="px-3 py-2 min-w-[200px]">Description / Payload</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#e2e8f0] dark:divide-[#334155] font-mono">
                  {rows.map((row) => {
                    const isSelected = selectedRow?._row_id === row._row_id;
                    const level = String(row.Level || '');
                    const isError = level.toLowerCase().includes('err') || level.toLowerCase().includes('crit');

                    return (
                      <tr
                        key={row._row_id}
                        onClick={() => setSelectedRow(row)}
                        onContextMenu={(e) => {
                          e.preventDefault();
                          setSelectedRow(row);
                          setContextMenu({
                            position: { x: e.clientX, y: e.clientY },
                            row,
                            cellValue: row.EventId,
                          });
                        }}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0f172a] dark:text-[#f8fafc]'
                            : 'hover:bg-slate-50 dark:hover:bg-[#1e293b]/60 text-[#0f172a] dark:text-[#f8fafc]'
                        }`}
                      >
                        <td className="px-3 py-1.5 font-bold text-[#0284c7] dark:text-[#38bdf8]">
                          {row.EventId}
                        </td>
                        <td className="px-3 py-1.5 text-slate-500 whitespace-nowrap text-[11px]">
                          {String(row.TimeCreated || '')}
                        </td>
                        <td className="px-3 py-1.5">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                              isError
                                ? 'bg-rose-100 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300'
                                : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300'
                            }`}
                          >
                            {level || 'Info'}
                          </span>
                        </td>
                        <td className="px-3 py-1.5 truncate max-w-[150px]" title={row.Channel}>
                          {row.Channel}
                        </td>
                        <td className="px-3 py-1.5 truncate max-w-[130px]" title={row.Computer}>
                          {row.Computer || '-'}
                        </td>
                        <td className="px-3 py-1.5 truncate max-w-[130px]" title={row.UserName}>
                          {row.UserName || '-'}
                        </td>
                        <td className="px-3 py-1.5 truncate max-w-[320px] font-sans" title={row.MapDescription || row.PayloadData1 || ''}>
                          {row.MapDescription || row.PayloadData1 || row.ExecutableInfo || '-'}
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

          {/* DRAGGABLE VERTICAL SPLITTER 2 (Between Center Table and Right Details Pane) */}
          <ResizeHandle
            orientation="vertical"
            onMouseDown={rightPane.handleMouseDown}
            onDoubleClick={rightPane.resetWidth}
            isDragging={rightPane.isDragging}
            title="Drag to resize Details Pane (double-click to reset)"
          />

          {/* Right Pane: Event Details & Raw XML / Payload View */}
          <div
            style={{ width: `${rightWidth}px` }}
            className="bg-[#f8fafc] dark:bg-[#0f172a] flex flex-col h-full overflow-hidden shrink-0 border-l border-[#cbd5e1] dark:border-[#334155]"
          >
            <div className="p-3 bg-white dark:bg-[#1e293b] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-amber-500" />
                <span className="font-bold text-xs uppercase tracking-wide text-[#0f172a] dark:text-[#f8fafc]">
                  Event Details & Payload
                </span>
              </div>
              {selectedRow && (
                <button
                  onClick={() =>
                    handleCopy(
                      JSON.stringify(selectedRow, null, 2),
                      'full_event'
                    )
                  }
                  className="p-1 rounded text-slate-500 hover:text-[#0284c7] transition-colors cursor-pointer"
                  title="Copy full JSON event"
                >
                  {copiedKey === 'full_event' ? (
                    <Check className="w-3.5 h-3.5 text-emerald-600" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              )}
            </div>

            {selectedRow ? (
              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {/* Event Summary Card */}
                <div className="p-3 bg-white dark:bg-[#1e293b] rounded border border-[#cbd5e1] dark:border-[#334155] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-extrabold text-sm text-[#0284c7] dark:text-[#38bdf8] font-mono">
                      Event ID {selectedRow.EventId}
                    </span>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-amber-50 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 font-bold border border-amber-200 dark:border-amber-800">
                      Record #{selectedRow.RecordNumber ?? selectedRow.EventRecordId}
                    </span>
                  </div>

                  <div className="space-y-1 text-xs">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Time (UTC):</span>
                      <span className="font-mono text-[11px]">{selectedRow.TimeCreated}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Provider:</span>
                      <span className="truncate max-w-[200px] text-right font-semibold">{selectedRow.Provider}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Channel:</span>
                      <span className="truncate max-w-[200px] text-right">{selectedRow.Channel}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Computer:</span>
                      <span className="font-mono">{selectedRow.Computer || '-'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">User:</span>
                      <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                        {selectedRow.UserName || '-'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Description / Message */}
                {selectedRow.MapDescription && (
                  <div className="p-3 bg-white dark:bg-[#1e293b] rounded border border-[#cbd5e1] dark:border-[#334155] space-y-1">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                      Event Description / Template
                    </span>
                    <p className="text-xs text-[#0f172a] dark:text-[#f8fafc] leading-relaxed">
                      {selectedRow.MapDescription}
                    </p>
                  </div>
                )}

                {/* Payload Data Fields */}
                <div className="p-3 bg-white dark:bg-[#1e293b] rounded border border-[#cbd5e1] dark:border-[#334155] space-y-2">
                  <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                    Extracted Payload Fields
                  </span>
                  <div className="space-y-1.5 text-xs font-mono">
                    {['PayloadData1', 'PayloadData2', 'PayloadData3', 'PayloadData4', 'PayloadData5', 'PayloadData6', 'ExecutableInfo', 'RemoteHost'].map((key) => {
                      const val = selectedRow[key];
                      if (!val) return null;
                      return (
                        <div key={key} className="p-1.5 rounded bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155]">
                          <span className="text-[10px] font-bold text-slate-400 block">{key}</span>
                          <span className="text-[11px] break-all select-all">{String(val)}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Raw XML / Payload Content */}
                {selectedRow.Payload && (
                  <div className="p-3 bg-white dark:bg-[#1e293b] rounded border border-[#cbd5e1] dark:border-[#334155] space-y-1">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                      Raw XML / Event Payload
                    </span>
                    <pre className="p-2 bg-[#f8fafc] dark:bg-[#0f172a] rounded text-[10px] font-mono whitespace-pre-wrap break-all max-h-56 overflow-y-auto border border-[#cbd5e1] dark:border-[#334155]">
                      {selectedRow.Payload}
                    </pre>
                  </div>
                )}
              </div>
            ) : (
              <div className="flex-1 flex items-center justify-center p-6 text-center text-slate-400 text-xs">
                Select an event record from the table to inspect details and full payload.
              </div>
            )}
          </div>
        </div>
      </main>

      {/* ------------------------------------------------------------- */}
      {/* MODAL 1: RAW EVENT PROFILES JSON EDITOR                       */}
      {/* ------------------------------------------------------------- */}
      {isRawModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 select-none">
          <div className="bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded-lg shadow-2xl w-full max-w-4xl flex flex-col max-h-[90vh] overflow-hidden font-sans">
            <div className="px-5 py-3.5 bg-[#f8fafc] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2.5">
                <div className="p-1.5 rounded bg-amber-100 dark:bg-amber-950/60 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-800">
                  <FileJson className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="font-bold text-sm text-[#0f172a] dark:text-[#f8fafc] flex items-center gap-2">
                    <span>Forensic Event Profiles Editor</span>
                    <span className="text-xs font-mono text-slate-400 font-normal">({rawFilePath})</span>
                  </h2>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Directly edit or extend the active JSON profiles configuration loaded by the DFIR engine
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsRawModalOpen(false)}
                className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex-1 overflow-hidden p-5 flex flex-col gap-3">
              {rawSaveError && (
                <div className="p-2.5 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 rounded flex items-center gap-2 text-xs text-rose-700 dark:text-rose-300 shrink-0">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{rawSaveError}</span>
                </div>
              )}

              {rawSaveSuccess && (
                <div className="p-2.5 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 rounded flex items-center gap-2 text-xs text-emerald-700 dark:text-emerald-300 shrink-0">
                  <Check className="w-4 h-4 shrink-0" />
                  <span>{rawFileName} saved successfully! Profiles updated.</span>
                </div>
              )}

              <div className="flex-1 flex flex-col min-h-[300px]">
                <textarea
                  value={rawEditorContent}
                  onChange={(e) => {
                    setRawEditorContent(e.target.value);
                    setRawSaveError(null);
                  }}
                  className="w-full flex-1 p-3 font-mono text-xs bg-slate-900 text-emerald-400 rounded border border-slate-700 focus:outline-none focus:border-[#0284c7] resize-none"
                  spellCheck={false}
                />
              </div>
            </div>

            <div className="px-5 py-3 bg-[#f8fafc] dark:bg-[#0f172a] border-t border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0">
              <span className="text-xs text-slate-400 font-mono">
                UTF-8 Validated JSON format
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setIsRawModalOpen(false)}
                  className="px-4 py-1.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white hover:bg-slate-100 dark:bg-[#1e293b] dark:hover:bg-[#334155] text-xs font-semibold text-slate-700 dark:text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleSaveRaw}
                  disabled={isSavingRaw}
                  className="px-4 py-1.5 rounded bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-semibold border border-[#0369a1] flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                >
                  <Save className="w-3.5 h-3.5" />
                  <span>{isSavingRaw ? 'Saving...' : 'Save Profiles File'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------- */}
      {/* MODAL 2: CREATE CUSTOM FORENSIC PROFILE                       */}
      {/* ------------------------------------------------------------- */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 select-none">
          <div className="bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded-lg shadow-2xl w-full max-w-lg flex flex-col max-h-[90vh] overflow-hidden font-sans">
            <div className="px-5 py-3.5 bg-[#f8fafc] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2.5">
                <div className="p-1.5 rounded bg-blue-100 dark:bg-blue-950/60 text-[#0284c7] dark:text-[#38bdf8] border border-blue-200 dark:border-blue-800">
                  <Plus className="w-4 h-4" />
                </div>
                <div>
                  <h2 className="font-bold text-sm text-[#0f172a] dark:text-[#f8fafc]">
                    Create Custom Forensic Profile
                  </h2>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Defines hunting criteria saved directly into rules/event_profiles.json
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsCreateModalOpen(false)}
                className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateProfile} className="p-5 space-y-3.5 overflow-y-auto">
              {createError && (
                <div className="p-2.5 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 rounded flex items-center gap-2 text-xs text-rose-700 dark:text-rose-300">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{createError}</span>
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold text-[#0f172a] dark:text-[#f8fafc] mb-1">
                  Profile Name <span className="text-rose-500">*</span>
                </label>
                <input
                  type="text"
                  required
                  value={createName}
                  onChange={(e) => setCreateName(e.target.value)}
                  placeholder="e.g., Suspicious PowerShell & Scripting"
                  className="w-full px-3 py-1.5 text-xs bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded focus:outline-none focus:border-[#0284c7] text-[#0f172a] dark:text-[#f8fafc]"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-[#0f172a] dark:text-[#f8fafc] mb-1">
                  Description
                </label>
                <input
                  type="text"
                  value={createDescription}
                  onChange={(e) => setCreateDescription(e.target.value)}
                  placeholder="e.g., Detects scriptblock execution and encoded command line arguments"
                  className="w-full px-3 py-1.5 text-xs bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded focus:outline-none focus:border-[#0284c7] text-[#0f172a] dark:text-[#f8fafc]"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-[#0f172a] dark:text-[#f8fafc] mb-1">
                  Event IDs (comma-separated)
                </label>
                <input
                  type="text"
                  value={createEventIds}
                  onChange={(e) => setCreateEventIds(e.target.value)}
                  placeholder="e.g., 4103, 4104, 4688"
                  className="w-full px-3 py-1.5 text-xs font-mono bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded focus:outline-none focus:border-[#0284c7] text-[#0f172a] dark:text-[#f8fafc]"
                />
                <p className="text-[10px] text-slate-400 mt-0.5">
                  Enter one or more numeric Event IDs separated by commas.
                </p>
              </div>

              <div>
                <label className="block text-xs font-semibold text-[#0f172a] dark:text-[#f8fafc] mb-1">
                  Channels (optional, comma-separated)
                </label>
                <input
                  type="text"
                  value={createChannels}
                  onChange={(e) => setCreateChannels(e.target.value)}
                  placeholder="e.g., Microsoft-Windows-PowerShell/Operational, Security"
                  className="w-full px-3 py-1.5 text-xs font-mono bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded focus:outline-none focus:border-[#0284c7] text-[#0f172a] dark:text-[#f8fafc]"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-[#0f172a] dark:text-[#f8fafc] mb-1">
                  Keywords (optional, comma-separated)
                </label>
                <input
                  type="text"
                  value={createKeywords}
                  onChange={(e) => setCreateKeywords(e.target.value)}
                  placeholder="e.g., -EncodedCommand, -enc, DownloadString, IEX"
                  className="w-full px-3 py-1.5 text-xs font-mono bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded focus:outline-none focus:border-[#0284c7] text-[#0f172a] dark:text-[#f8fafc]"
                />
              </div>

              <div className="pt-3 flex items-center justify-end gap-2 border-t border-[#cbd5e1] dark:border-[#334155]">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-1.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white hover:bg-slate-100 dark:bg-[#1e293b] dark:hover:bg-[#334155] text-xs font-semibold text-slate-700 dark:text-slate-300 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isCreatingProfile}
                  className="px-4 py-1.5 rounded bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-semibold border border-[#0369a1] flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>{isCreatingProfile ? 'Saving...' : 'Create Profile'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Native Magnet AXIOM-style Right-Click Forensic Context Menu */}
      {contextMenu && (
        <RowContextMenu
          caseId={caseId}
          position={contextMenu.position}
          onClose={() => setContextMenu(null)}
          row={contextMenu.row}
          tableName="raw_evtx"
          cellValue={contextMenu.cellValue}
        />
      )}
    </div>
  );
};
