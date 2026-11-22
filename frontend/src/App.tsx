import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  apiClient,
  CaseSummary,
  ArtifactRegistryResponse,
  ArtifactItem,
} from './api/client';
import { TopNavBar, TabType } from './components/TopNavBar';
import { GlobalFilterBar, GlobalFilterState } from './components/GlobalFilterBar';
import { SidebarTree, buildSubviewDedupPredicate } from './components/SidebarTree';
import { ArtifactGrid } from './components/ArtifactGrid';
import { DetailsAndHexPane } from './components/DetailsAndHexPane';
import { TimelineExplorer } from './components/TimelineExplorer';
import { ProcessWizard, ProcessWizardPersistedState } from './components/ProcessWizard';
import { CaseDashboard } from './components/CaseDashboard';
import { KeywordManager } from './components/KeywordManagerModal';
import { RegRipperExplorer } from './components/RegRipperExplorer';
import { EventLogsWorkbench } from './components/EventLogsWorkbench';
import { FileSystemView } from './components/FileSystemView';
import { MalwareWorkbench } from './components/MalwareWorkbench';
import { ToolPathsModal } from './components/ToolPathsModal';
import { ConnectionsDrawer } from './components/ConnectionsDrawer';
import { FileBrowserModal } from './components/FileBrowserModal';
import { CustomExportRequestDetail } from './components/RowContextMenu';
import { useResizable, ResizeHandle } from './components/ResizeHandle';

export const App: React.FC = () => {
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    try {
      const stored = localStorage.getItem('wft_theme');
      if (stored === 'dark' || stored === 'light') return stored;
    } catch {
      // fallback
    }
    return 'light';
  });

  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [currentCaseId, setCurrentCaseId] = useState<string>('');
  const [isLoadingCases, setIsLoadingCases] = useState<boolean>(true);

  const [activeTab, setActiveTab] = useState<TabType>('artifacts');
  const [isNewCaseModalOpen, setIsNewCaseModalOpen] = useState<boolean>(false);
  const [isKeywordManagerOpen, setIsKeywordManagerOpen] = useState<boolean>(false);
  const [isToolPathsModalOpen, setIsToolPathsModalOpen] = useState<boolean>(false);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  const loadInitialProcessingSessions = (): Record<string, ProcessWizardPersistedState> => {
    try {
      const raw = sessionStorage.getItem('wft_process_sessions_v1');
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') return parsed;
      }
    } catch {
      // ignore sessionStorage errors
    }
    return {};
  };

  const [processingSessions, setProcessingSessions] = useState<
    Record<string, ProcessWizardPersistedState>
  >(loadInitialProcessingSessions);
  const [processTabState, setProcessTabState] = useState<ProcessWizardPersistedState | null>(() => {
    const sessions = loadInitialProcessingSessions();
    const activeRunning = Object.values(sessions).find(
      (s) => s && s.activeCaseId && s.statusData?.status === 'RUNNING'
    );
    return activeRunning || null;
  });

  const handlePersistProcessState = useCallback(
    (state: ProcessWizardPersistedState, commitForCaseId?: string) => {
      setProcessTabState(state);
      const targetCid = commitForCaseId || state.activeCaseId;
      if (targetCid) {
        setProcessingSessions((prev) => {
          const next = { ...prev, [targetCid]: state };
          try {
            sessionStorage.setItem('wft_process_sessions_v1', JSON.stringify(next));
          } catch {
            // ignore storage quota errors
          }
          return next;
        });
      }
    },
    []
  );

  const isProcessingRunning = Boolean(
    processTabState?.statusData?.status === 'RUNNING' ||
      (currentCaseId && processingSessions[currentCaseId]?.statusData?.status === 'RUNNING')
  );

  const [globalFilterState, setGlobalFilterState] = useState<GlobalFilterState>({
    evidenceSource: undefined,
    artifactTable: undefined,
    contentTypes: [],
    dateRange: { preset: 'all' },
    keywords: [],
    tags: [],
    bookmarkedOnly: false,
    search: '',
  });

  const [registryData, setRegistryData] = useState<ArtifactRegistryResponse | null>(null);
  const [isLoadingRegistry, setIsLoadingRegistry] = useState<boolean>(false);
  const [selectedArtifact, setSelectedArtifact] = useState<ArtifactItem | null>(null);
  const [selectedRowState, setSelectedRowState] = useState<{
    caseId: string;
    row: Record<string, unknown>;
  } | null>(null);
  const userSelectedCaseRef = useRef<string>(
    processTabState?.statusData?.status === 'RUNNING' ? processTabState.activeCaseId : ''
  );
  const currentCaseIdRef = useRef<string>('');
  currentCaseIdRef.current = currentCaseId;
  const selectedRow =
    selectedRowState && selectedRowState.caseId === currentCaseId ? selectedRowState.row : null;
  const setSelectedRow = useCallback((row: Record<string, unknown> | null) => {
    if (!row) {
      setSelectedRowState(null);
    } else {
      setSelectedRowState({ caseId: currentCaseIdRef.current, row });
    }
  }, []);
  const [selectedRegRipperPlugin, setSelectedRegRipperPlugin] = useState<string | null>(null);

  // Cross-workbench forensic pivots, Connections Graph drawer, and Custom Destination Export modal
  const [caseMaxTimestampUtc, setCaseMaxTimestampUtc] = useState<string | null>(null);
  const [drawerEntity, setDrawerEntity] = useState<string | null>(null);
  const [fsJumpPath, setFsJumpPath] = useState<string | null>(null);
  const [timelinePivot, setTimelinePivot] = useState<{ aroundTimestamp: string; windowMinutes: number } | null>(
    null
  );
  const [customExportRequest, setCustomExportRequest] = useState<CustomExportRequestDetail | null>(null);
  const [exportToast, setExportToast] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const artifactsContainerRef = useRef<HTMLDivElement>(null);
  const artifactsLeft = useResizable({
    initialWidth: 320,
    minWidth: 200,
    maxWidth: 600,
    storageKey: 'wft_artifacts_left_width',
    direction: 'left',
    containerRef: artifactsContainerRef,
    minCenterWidth: 280,
  });
  const artifactsRight = useResizable({
    initialWidth: 400,
    minWidth: 260,
    maxWidth: 750,
    storageKey: 'wft_artifacts_right_width',
    direction: 'right',
    containerRef: artifactsContainerRef,
    otherWidth: artifactsLeft.width,
    minCenterWidth: 280,
  });

  useEffect(() => {
    try {
      localStorage.setItem('wft_theme', theme);
    } catch (e) {
      console.warn('Unable to persist theme to localStorage', e);
    }
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [theme]);

  useEffect(() => {
    const handleContextMenu = (e: MouseEvent) => {
      const target = e.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.isContentEditable)
      ) {
        return;
      }
      e.preventDefault();
    };
    window.addEventListener('contextmenu', handleContextMenu);
    return () => window.removeEventListener('contextmenu', handleContextMenu);
  }, []);

  const handleInspectEntity = useCallback((entityValue: string) => {
    setDrawerEntity(entityValue ?? '');
  }, []);

  const handleJumpToFileSystem = useCallback((filePath: string) => {
    if (!filePath) return;
    setFsJumpPath(filePath);
    setActiveTab('filesystem');
  }, []);

  useEffect(() => {
    const onOpenCustomExport = (ev: Event) => {
      const detail = (ev as CustomEvent<CustomExportRequestDetail>).detail;
      if (detail && detail.caseId) {
        setCustomExportRequest(detail);
      }
    };
    const onInspectEntityEvent = (ev: Event) => {
      const detail = (ev as CustomEvent<{ entityValue?: string }>).detail;
      if (detail && typeof detail.entityValue === 'string') {
        setDrawerEntity(detail.entityValue);
      }
    };
    const onPivotTimelineEvent = (ev: Event) => {
      const detail = (ev as CustomEvent<{ aroundTimestamp?: string; windowMinutes?: number }>).detail;
      if (detail?.aroundTimestamp) {
        setTimelinePivot({
          aroundTimestamp: detail.aroundTimestamp,
          windowMinutes: detail.windowMinutes || 5,
        });
        setActiveTab('timeline');
      }
    };

    window.addEventListener('wft:open-custom-export', onOpenCustomExport);
    window.addEventListener('wft:inspect-entity', onInspectEntityEvent);
    window.addEventListener('wft:pivot-timeline', onPivotTimelineEvent);
    return () => {
      window.removeEventListener('wft:open-custom-export', onOpenCustomExport);
      window.removeEventListener('wft:inspect-entity', onInspectEntityEvent);
      window.removeEventListener('wft:pivot-timeline', onPivotTimelineEvent);
    };
  }, []);

  const handleToggleTheme = () => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  };

  const loadCases = useCallback(async (selectCaseId?: string) => {
    setIsLoadingCases(true);
    try {
      const res = await apiClient.listCases();
      const deduped = Array.from(
        new Map(res.cases.map((c) => [(c.case_path || c.case_id).toLowerCase(), c])).values()
      );
      setCases(deduped);
      if (deduped.length > 0) {
        if (selectCaseId && deduped.some((c) => c.case_id === selectCaseId)) {
          userSelectedCaseRef.current = selectCaseId;
          setCurrentCaseId(selectCaseId);
        } else {
          setCurrentCaseId((prev) => {
            const pinned = userSelectedCaseRef.current || prev;
            if (pinned && deduped.some((c) => c.case_id === pinned)) {
              return pinned;
            }
            const prefCase =
              deduped.find((c) => c.total_artifact_rows > 0) ||
              deduped[0];
            return prefCase.case_id;
          });
        }
      } else {
        userSelectedCaseRef.current = '';
        setCurrentCaseId('');
        setActiveTab('process');
        setRegistryData(null);
        setSelectedArtifact(null);
        setSelectedRow(null);
      }
    } catch (err) {
      console.error('Failed to list cases:', err);
    } finally {
      setIsLoadingCases(false);
    }
  }, [setSelectedRow]);

  useEffect(() => {
    loadCases();
  }, [loadCases]);

  const handleDeleteCase = async (caseId: string) => {
    try {
      await apiClient.deleteCase(caseId);
      if (userSelectedCaseRef.current === caseId) {
        userSelectedCaseRef.current = '';
      }
      if (currentCaseId === caseId) {
        setCurrentCaseId('');
        setSelectedRow(null);
        setSelectedArtifact(null);
        setRegistryData(null);
      }
      await loadCases();
    } catch (err: any) {
      console.error('Failed to delete case:', err);
      alert(`Failed to delete case: ${err?.message || err}`);
    }
  };

  const loadRegistry = useCallback(async (caseId: string) => {
    if (!caseId) return;
    setIsLoadingRegistry(true);
    try {
      const reg = await apiClient.getArtifactRegistry(caseId);
      setRegistryData(reg);
      if (reg.artifacts.length > 0) {
        setSelectedArtifact((prev) => {
          if (prev && reg.artifacts.some((a) => a.table_name === prev.table_name && a.row_count > 0)) {
            return prev;
          }
          return null;
        });
      } else {
        setSelectedArtifact(null);
      }
    } catch (err) {
      console.error(`Failed to load registry for case ${caseId}:`, err);
      setRegistryData(null);
      setSelectedArtifact(null);
    } finally {
      setIsLoadingRegistry(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    setCaseMaxTimestampUtc(null);
    if (currentCaseId) {
      loadRegistry(currentCaseId);
      setSelectedRow(null);
      setDrawerEntity(null);
      setTimelinePivot(null);
      apiClient
        .getTimelineStats(currentCaseId)
        .then((stats) => {
          if (!cancelled) {
            setCaseMaxTimestampUtc(stats.max_timestamp_utc || null);
          }
        })
        .catch(() => {
          if (!cancelled) {
            setCaseMaxTimestampUtc(null);
          }
        });
    }
    return () => {
      cancelled = true;
    };
  }, [currentCaseId, loadRegistry, setSelectedRow]);

  useEffect(() => {
    if (globalFilterState.artifactTable && registryData?.artifacts) {
      const match = registryData.artifacts.find(
        (a) => a.table_name === globalFilterState.artifactTable
      );
      if (match) {
        setSelectedArtifact(match);
        setSelectedRow(null);
        setActiveTab('artifacts');
      }
    }
  }, [globalFilterState.artifactTable, registryData?.artifacts]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      await loadCases(currentCaseId);
      if (currentCaseId) {
        await loadRegistry(currentCaseId);
      }
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    const runningCaseId =
      processTabState?.statusData?.status === 'RUNNING' ? processTabState.activeCaseId : null;
    if (!runningCaseId || activeTab === 'process' || isNewCaseModalOpen) return;

    let cancelled = false;
    const poll = async () => {
      try {
        const res = await apiClient.getCaseStatus(runningCaseId);
        if (cancelled) return;
        setProcessTabState((prev) =>
          prev && prev.activeCaseId === runningCaseId ? { ...prev, statusData: res } : prev
        );
        setProcessingSessions((prev) => {
          const existing = prev[runningCaseId];
          if (!existing) return prev;
          const next = { ...prev, [runningCaseId]: { ...existing, statusData: res } };
          try {
            sessionStorage.setItem('wft_process_sessions_v1', JSON.stringify(next));
          } catch {
            // ignore
          }
          return next;
        });
        if (res.status === 'SUCCESS' || res.status === 'COMPLETED') {
          loadCases(runningCaseId);
          loadRegistry(runningCaseId);
        }
      } catch {
        // ignore transient poll errors
      }
    };
    const timer = window.setInterval(poll, 2500);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [
    processTabState?.statusData?.status,
    processTabState?.activeCaseId,
    activeTab,
    isNewCaseModalOpen,
    loadCases,
    loadRegistry,
  ]);

  const handleCaseCreated = (newCaseId: string) => {
    if (newCaseId) {
      userSelectedCaseRef.current = newCaseId;
    }
    loadCases(newCaseId);
  };

  const handleExploreCategory = (category: string, tableName?: string) => {
    setActiveTab('artifacts');
    if (registryData?.artifacts) {
      if (tableName) {
        const match = registryData.artifacts.find(
          (a) =>
            a.table_name === tableName ||
            a.artifact_id === tableName ||
            (tableName === 'bulk_extractor_hits' &&
              a.table_name === 'parsed_bulk_extractor_features') ||
            (tableName === 'carved_files' && a.table_name === 'parsed_carved_files')
        );
        if (match) {
          setSelectedArtifact(match);
          setSelectedRow(null);
          return;
        }
      }
      const matchCat = registryData.artifacts.find(
        (a) => a.category.toLowerCase() === category.toLowerCase()
      );
      if (matchCat) {
        setSelectedArtifact(matchCat);
        setSelectedRow(null);
      }
    }
  };

  const dedupedArtifacts = useMemo(() => {
    const list = registryData?.artifacts || [];
    const isDuplicateSubview = buildSubviewDedupPredicate(list);
    return list.filter((a) => !isDuplicateSubview(a));
  }, [registryData?.artifacts]);

  const totalAllArtifactRows = useMemo(() => {
    const computed = dedupedArtifacts.reduce((acc, a) => acc + (a.row_count || 0), 0);
    if (
      typeof registryData?.all_evidence_total === 'number' &&
      registryData.all_evidence_total > 0 &&
      registryData.all_evidence_total === computed
    ) {
      return registryData.all_evidence_total;
    }
    return computed;
  }, [dedupedArtifacts, registryData?.all_evidence_total]);

  const totalRegRipperPlugins =
    registryData?.artifacts.find((a) => a.artifact_id === 'regripper_plugins')?.row_count || 0;

  const totalEvtxCount =
    registryData?.artifacts.find((a) => a.table_name === 'raw_evtx')?.row_count || 0;

  const totalMalwareHits = useMemo(() => {
    const list = registryData?.artifacts || [];
    const seenMalwareTables = new Set<string>();
    let sum = 0;
    for (const a of list) {
      if (
        (a.table_name === 'artifact_stinger_hits' ||
          a.table_name === 'artifact_yara_hits' ||
          a.table_name === 'parsed_suspicious_binaries') &&
        !seenMalwareTables.has(a.table_name)
      ) {
        seenMalwareTables.add(a.table_name);
        sum += a.row_count || 0;
      }
    }
    if (sum > 0) {
      return sum;
    }
    const unionView = list.find((a) => a.table_name === 'view_all_malware_detections');
    return unionView?.row_count || 0;
  }, [registryData?.artifacts]);

  const totalFileSystemCount =
    registryData?.artifacts.find(
      (a) => a.table_name === 'raw_mft' || a.artifact_id === 'os_mft'
    )?.row_count || 0;

  const populatedArtifacts = useMemo(
    () => dedupedArtifacts.filter((a) => a.row_count > 0),
    [dedupedArtifacts]
  );

  const effectiveArtifact: ArtifactItem | null =
    selectedArtifact ||
    (registryData?.artifacts && registryData.artifacts.length > 0
      ? (registryData.timeline_total || 0) > 0
        ? {
            artifact_id: 'all_evidence',
            category: 'ALL EVIDENCE',
            display_name: 'ALL EVIDENCE',
            table_name: 'master_timeline',
            source_tool: 'Master Timeline',
            row_count: totalAllArtifactRows || registryData.timeline_total,
            last_updated: '',
          }
        : populatedArtifacts[0] || {
            artifact_id: 'all_evidence',
            category: 'ALL EVIDENCE',
            display_name: 'ALL EVIDENCE',
            table_name: 'master_timeline',
            source_tool: 'Master Timeline',
            row_count: totalAllArtifactRows,
            last_updated: '',
          }
      : null);

  const handleTopNavExportCsv = useCallback(() => {
    if (!currentCaseId) return;
    const targetTable = effectiveArtifact?.table_name || 'master_timeline';
    const csvUrl = apiClient.getTableExportCsvUrl(
      currentCaseId,
      targetTable,
      globalFilterState.search || undefined
    );
    const a = document.createElement('a');
    a.href = csvUrl;
    a.download = `${currentCaseId}_${targetTable}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }, [currentCaseId, effectiveArtifact?.table_name, globalFilterState.search]);

  const handleTopNavExportHtmlReport = useCallback(async () => {
    if (!currentCaseId) return;
    try {
      await apiClient.exportCaseReportHtml(currentCaseId);
    } catch (err: any) {
      console.error('Failed to export HTML report:', err);
    }
  }, [currentCaseId]);

  const handleConfirmCustomExportFolder = useCallback(
    async (destinationDir: string) => {
      const req = customExportRequest;
      setCustomExportRequest(null);
      if (!req || !destinationDir) return;
      try {
        const res = await apiClient.saveToFolder(req.caseId, {
          path: req.filePath,
          file_path: req.filePath,
          destination_dir: destinationDir,
          is_folder: req.isFolder,
          table_name: req.tableName,
          row_id: req.rowId,
        });
        const savedTarget = res.saved_path || res.destination_dir || res.destination_folder || destinationDir;
        setExportToast({
          type: 'success',
          text: `Exported successfully to ${savedTarget}`,
        });
        window.setTimeout(() => setExportToast(null), 4500);
      } catch (err: any) {
        setExportToast({
          type: 'error',
          text: `Export failed: ${err?.message || String(err)}`,
        });
        window.setTimeout(() => setExportToast(null), 5000);
      }
    },
    [customExportRequest]
  );

  return (
    <div className="flex flex-col h-screen w-screen bg-[#f1f5f9] dark:bg-[#0f172a] text-[#0f172a] dark:text-[#f8fafc] overflow-hidden font-sans">
      <div className="order-1 shrink-0">
        <TopNavBar
          cases={cases}
          currentCaseId={currentCaseId}
          onSelectCase={(cid) => {
            userSelectedCaseRef.current = cid;
            setCurrentCaseId(cid);
            setSelectedRow(null);
            if (processingSessions[cid]) {
              setProcessTabState(processingSessions[cid]);
            } else if (processTabState?.statusData?.status !== 'RUNNING') {
              setProcessTabState(null);
            }
          }}
          onDeleteCase={handleDeleteCase}
          activeTab={activeTab}
          onChangeTab={setActiveTab}
          onOpenNewCaseModal={() => setIsNewCaseModalOpen(true)}
          onOpenKeywordManager={() => setIsKeywordManagerOpen(true)}
          onOpenToolPaths={() => setIsToolPathsModalOpen(true)}
          onOpenConnections={() => setDrawerEntity('')}
          onExportCsv={handleTopNavExportCsv}
          onExportHtmlReport={handleTopNavExportHtmlReport}
          onRefresh={handleRefresh}
          isRefreshing={isRefreshing}
          isProcessingRunning={isProcessingRunning}
          totalArtifacts={totalAllArtifactRows}
          totalTimeline={registryData?.timeline_total || 0}
          totalEvtx={totalEvtxCount}
          totalFileSystem={totalFileSystemCount}
          totalMalwareHits={totalMalwareHits}
          totalRegRipperPlugins={totalRegRipperPlugins}
          theme={theme}
          onToggleTheme={handleToggleTheme}
        />
      </div>

      <main className="flex-1 flex overflow-hidden relative order-3">
        {activeTab === 'dashboard' && (
          <div className="flex-1 h-full overflow-hidden">
            <CaseDashboard
              caseId={currentCaseId}
              onExploreArtifact={handleExploreCategory}
              onGoToTimeline={() => setActiveTab('timeline')}
              onGoToEventLogs={() => setActiveTab('eventlogs')}
              onGoToMalware={() => setActiveTab('malware')}
              onGoToFileSystem={() => setActiveTab('filesystem')}
              onGoToRegRipper={() => setActiveTab('regripper')}
              onOpenKeywordManager={() => setIsKeywordManagerOpen(true)}
              onInspectEntity={handleInspectEntity}
            />
          </div>
        )}

        {activeTab === 'artifacts' && (
          <div ref={artifactsContainerRef} className="flex-1 flex overflow-hidden w-full h-full relative">
            <SidebarTree
              width={artifactsLeft.width}
              registryData={registryData}
              selectedTable={selectedArtifact?.table_name || null}
              onSelectArtifact={(art) => {
                setSelectedArtifact(art);
                setSelectedRow(null);
                setGlobalFilterState((prev) => ({
                  ...prev,
                  artifactTable: art?.table_name,
                }));
              }}
              isLoading={isLoadingRegistry}
              contentTypes={globalFilterState.contentTypes}
              onClearContentTypes={() =>
                setGlobalFilterState((prev) => ({ ...prev, contentTypes: [] }))
              }
            />

            <ResizeHandle
              orientation="vertical"
              onMouseDown={artifactsLeft.handleMouseDown}
              onDoubleClick={artifactsLeft.resetWidth}
              isDragging={artifactsLeft.isDragging}
              title="Drag to resize Category Tree (double-click to reset)"
            />

            <div className="flex-1 flex flex-col overflow-hidden min-w-0">
              <ArtifactGrid
                caseId={currentCaseId}
                selectedArtifact={effectiveArtifact}
                onSelectRow={setSelectedRow}
                onInspectEntity={handleInspectEntity}
                globalSearch={globalFilterState.search}
                externalKeywords={globalFilterState.keywords}
                dateRange={globalFilterState.dateRange}
                tags={globalFilterState.tags}
                bookmarkedOnly={globalFilterState.bookmarkedOnly}
              />
            </div>

            <ResizeHandle
              orientation="vertical"
              onMouseDown={artifactsRight.handleMouseDown}
              onDoubleClick={artifactsRight.resetWidth}
              isDragging={artifactsRight.isDragging}
              title="Drag to resize Details & Preview pane (double-click to reset)"
            />

            <DetailsAndHexPane
              width={artifactsRight.width}
              caseId={currentCaseId}
              tableName={effectiveArtifact?.table_name || null}
              selectedRow={selectedRow}
              onInspectEntity={handleInspectEntity}
              onJumpToFileSystem={handleJumpToFileSystem}
              onBookmarkCreated={handleRefresh}
            />
          </div>
        )}

        {activeTab === 'regripper' && (
          <div className="flex-1 h-full overflow-hidden">
            <RegRipperExplorer
              caseId={currentCaseId}
              onInspectEntity={handleInspectEntity}
              selectedPluginName={selectedRegRipperPlugin}
              onSelectPlugin={setSelectedRegRipperPlugin}
              globalSearch={globalFilterState.search}
              dateRange={globalFilterState.dateRange}
              externalKeywords={globalFilterState.keywords}
              tags={globalFilterState.tags}
              bookmarkedOnly={globalFilterState.bookmarkedOnly}
            />
          </div>
        )}

        {activeTab === 'eventlogs' && (
          <div className="flex-1 h-full overflow-hidden">
            <EventLogsWorkbench
              caseId={currentCaseId}
              globalSearch={globalFilterState.search}
              dateRange={globalFilterState.dateRange}
              externalKeywords={globalFilterState.keywords}
              tags={globalFilterState.tags}
              bookmarkedOnly={globalFilterState.bookmarkedOnly}
              onInspectEntity={handleInspectEntity}
            />
          </div>
        )}

        {activeTab === 'filesystem' && (
          <div className="flex-1 h-full overflow-hidden">
            <FileSystemView
              caseId={currentCaseId}
              globalFilterState={globalFilterState}
              initialTargetPath={fsJumpPath}
              onClearInitialTargetPath={() => setFsJumpPath(null)}
              onInspectEntity={handleInspectEntity}
            />
          </div>
        )}

        {activeTab === 'malware' && (
          <div className="flex-1 h-full overflow-hidden">
            <MalwareWorkbench
              caseId={currentCaseId}
              globalSearch={globalFilterState.search}
              dateRange={globalFilterState.dateRange}
              externalKeywords={globalFilterState.keywords}
              tags={globalFilterState.tags}
              bookmarkedOnly={globalFilterState.bookmarkedOnly}
              onInspectEntity={handleInspectEntity}
              onScanCompleted={handleRefresh}
            />
          </div>
        )}

        {activeTab === 'timeline' && (
          <div className="flex-1 h-full overflow-hidden">
            <TimelineExplorer
              caseId={currentCaseId}
              onInspectEntity={handleInspectEntity}
              onNavigateToArtifact={(tableName) => {
                handleExploreCategory('', tableName);
              }}
              globalSearch={globalFilterState.search}
              dateRange={globalFilterState.dateRange}
              externalKeywords={globalFilterState.keywords}
              tags={globalFilterState.tags}
              bookmarkedOnly={globalFilterState.bookmarkedOnly}
              externalPivot={timelinePivot}
              onClearExternalPivot={() => setTimelinePivot(null)}
            />
          </div>
        )}

        {activeTab === 'process' && (
          <div className="flex-1 h-full overflow-hidden">
            <ProcessWizard
              currentCaseId={currentCaseId}
              onCaseCreated={handleCaseCreated}
              isOpenAsModal={false}
              persistedState={
                processTabState &&
                (processTabState.statusData?.status === 'RUNNING' ||
                  processTabState.activeCaseId === currentCaseId)
                  ? processTabState
                  : currentCaseId
                  ? processingSessions[currentCaseId] || null
                  : null
              }
              onPersistState={handlePersistProcessState}
              onProcessingComplete={() => {
                handleRefresh();
              }}
              onNavigateToExamine={() => setActiveTab('artifacts')}
            />
          </div>
        )}

        {/* Slide-over Magnet AXIOM Entity Connections Graph Drawer */}
        {drawerEntity !== null && currentCaseId && (
          <div
            data-testid="connections-drawer-overlay"
            className="absolute inset-y-0 right-0 z-40 w-full max-w-[680px] shadow-2xl border-l border-[#cbd5e1] dark:border-[#334155] flex"
          >
            <ConnectionsDrawer
              caseId={currentCaseId}
              activeEntity={drawerEntity}
              onSelectEntity={(val) => setDrawerEntity(val)}
              onNavigateToSource={(sourceTable) => {
                setDrawerEntity(null);
                handleExploreCategory('', sourceTable);
              }}
              onClose={() => setDrawerEntity(null)}
              isFullScreen={false}
              width={680}
            />
          </div>
        )}
      </main>

      <div className="order-2 shrink-0">
        <GlobalFilterBar
          caseId={currentCaseId}
          filterState={globalFilterState}
          onFilterChange={setGlobalFilterState}
          onOpenKeywordManager={() => setIsKeywordManagerOpen(true)}
          artifacts={registryData?.artifacts}
          totalAllRows={totalAllArtifactRows}
          maxTimestampUtc={caseMaxTimestampUtc}
          onSelectRegRipperPlugin={(pluginName) => {
            setSelectedRegRipperPlugin(pluginName);
            setActiveTab('regripper');
          }}
          selectedRegRipperPlugin={selectedRegRipperPlugin}
          onNavigateToRegRipper={() => setActiveTab('regripper')}
        />
      </div>

      {exportToast && (
        <div
          data-testid="custom-export-toast"
          className={`order-2 px-4 py-1.5 text-xs font-mono flex items-center justify-between border-b shrink-0 ${
            exportToast.type === 'success'
              ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-200 border-emerald-200 dark:border-emerald-800'
              : 'bg-rose-50 dark:bg-rose-950/60 text-rose-800 dark:text-rose-200 border-rose-200 dark:border-rose-800'
          }`}
        >
          <span>{exportToast.text}</span>
          <button
            type="button"
            onClick={() => setExportToast(null)}
            className="ml-3 underline cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {customExportRequest && (
        <FileBrowserModal
          isOpen={Boolean(customExportRequest)}
          onClose={() => setCustomExportRequest(null)}
          onSelect={handleConfirmCustomExportFolder}
          mode="folder"
          title={`Select Destination Folder to Export ${
            customExportRequest.filePath || customExportRequest.tableName || 'Evidence'
          }`}
        />
      )}

      {isKeywordManagerOpen && (
        <KeywordManager
          caseId={currentCaseId}
          isOpen={isKeywordManagerOpen}
          onClose={() => setIsKeywordManagerOpen(false)}
          isModal={true}
          onKeywordsUpdated={handleRefresh}
          selectedKeywordFilters={globalFilterState.keywords}
          onToggleKeywordFilter={(kw) => {
            const next = globalFilterState.keywords.includes(kw)
              ? globalFilterState.keywords.filter((k) => k !== kw)
              : [...globalFilterState.keywords, kw];
            setGlobalFilterState({ ...globalFilterState, keywords: next });
          }}
        />
      )}

      {isToolPathsModalOpen && (
        <ToolPathsModal
          isOpen={isToolPathsModalOpen}
          onClose={() => setIsToolPathsModalOpen(false)}
          onPathsUpdated={handleRefresh}
        />
      )}

      {isNewCaseModalOpen && (
        <div className="fixed inset-0 z-[60] bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded-lg max-w-7xl w-full max-h-[92vh] overflow-hidden shadow-2xl flex flex-col text-[#0f172a] dark:text-[#f8fafc]">
            <ProcessWizard
              currentCaseId={currentCaseId}
              onCaseCreated={(newCid) => {
                handleCaseCreated(newCid);
              }}
              isOpenAsModal={true}
              persistedState={isProcessingRunning ? processTabState : null}
              onPersistState={handlePersistProcessState}
              onProcessingComplete={() => {
                handleRefresh();
              }}
              onCloseModal={() => setIsNewCaseModalOpen(false)}
              onNavigateToExamine={() => {
                setActiveTab('artifacts');
                setIsNewCaseModalOpen(false);
              }}
            />
          </div>
        </div>
      )}
    </div>
  );
};

export default App;