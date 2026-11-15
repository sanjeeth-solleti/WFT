import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  apiClient,
  CaseSummary,
  ArtifactRegistryResponse,
  ArtifactItem,
} from './api/client';
import { TopNavBar, TabType } from './components/TopNavBar';
import { GlobalFilterBar, GlobalFilterState } from './components/GlobalFilterBar';
import { SidebarTree } from './components/SidebarTree';
import { ArtifactGrid } from './components/ArtifactGrid';
import { DetailsAndHexPane } from './components/DetailsAndHexPane';
import { TimelineExplorer } from './components/TimelineExplorer';
import { ProcessWizard } from './components/ProcessWizard';
import { CaseDashboard } from './components/CaseDashboard';
import { KeywordManager } from './components/KeywordManagerModal';
import { RegRipperExplorer } from './components/RegRipperExplorer';
import { EventLogsWorkbench } from './components/EventLogsWorkbench';
import { FileSystemView } from './components/FileSystemView';
import { MalwareWorkbench } from './components/MalwareWorkbench';
import { ToolPathsModal } from './components/ToolPathsModal';
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

  const [globalFilterState, setGlobalFilterState] = useState<GlobalFilterState>({
    evidenceSource: undefined,
    artifactTable: undefined,
    contentTypes: [],
    dateRange: { preset: 'all' },
    keywords: [],
    tags: [],
    search: '',
  });

  const [registryData, setRegistryData] = useState<ArtifactRegistryResponse | null>(null);
  const [isLoadingRegistry, setIsLoadingRegistry] = useState<boolean>(false);
  const [selectedArtifact, setSelectedArtifact] = useState<ArtifactItem | null>(null);
  const [selectedRow, setSelectedRow] = useState<Record<string, unknown> | null>(null);
  const [selectedRegRipperPlugin, setSelectedRegRipperPlugin] = useState<string | null>(null);

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
      e.preventDefault();
    };
    window.addEventListener('contextmenu', handleContextMenu);
    return () => window.removeEventListener('contextmenu', handleContextMenu);
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
          setCurrentCaseId(selectCaseId);
        } else if (!currentCaseId || !deduped.some((c) => c.case_id === currentCaseId)) {
          const prefCase =
            deduped.find((c) => c.total_artifact_rows > 0) ||
            deduped[0];
          setCurrentCaseId(prefCase.case_id);
        }
      } else {
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
  }, [currentCaseId]);

  useEffect(() => {
    loadCases();
  }, [loadCases]);

  const handleDeleteCase = async (caseId: string) => {
    try {
      await apiClient.deleteCase(caseId);
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
    if (currentCaseId) {
      loadRegistry(currentCaseId);
      setSelectedRow(null);
    }
  }, [currentCaseId, loadRegistry]);

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

  const handleCaseCreated = (newCaseId: string) => {
    loadCases(newCaseId);
  };

  const handleExploreCategory = (category: string, tableName?: string) => {
    setActiveTab('artifacts');
    if (registryData?.artifacts) {
      if (tableName) {
        const match = registryData.artifacts.find((a) => a.table_name === tableName);
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

  const totalAllArtifactRows =
    registryData?.artifacts.reduce((acc, a) => acc + a.row_count, 0) || 0;

  const totalRegRipperPlugins =
    registryData?.artifacts.find((a) => a.artifact_id === 'regripper_plugins')?.row_count || 0;

  const totalEvtxCount =
    registryData?.artifacts.find((a) => a.table_name === 'raw_evtx')?.row_count || 0;

  const totalMalwareHits =
    registryData?.artifacts.find(
      (a) =>
        a.table_name === 'view_all_malware_detections' ||
        a.table_name === 'artifact_stinger_hits' ||
        a.table_name === 'artifact_yara_hits'
    )?.row_count || 0;

  const totalFileSystemCount =
    registryData?.artifacts.find(
      (a) => a.table_name === 'raw_mft' || a.artifact_id === 'os_mft'
    )?.row_count || 0;

  const effectiveArtifact: ArtifactItem | null =
    selectedArtifact ||
    (registryData?.artifacts && registryData.artifacts.length > 0
      ? {
          artifact_id: 'all_evidence',
          category: 'ALL EVIDENCE',
          display_name: 'ALL EVIDENCE',
          table_name: 'master_timeline',
          source_tool: 'Master Timeline',
          row_count: registryData.timeline_total || totalAllArtifactRows,
          last_updated: '',
        }
      : null);

  return (
    <div className="flex flex-col h-screen w-screen bg-[#f1f5f9] dark:bg-[#0f172a] text-[#0f172a] dark:text-[#f8fafc] overflow-hidden font-sans">
      <TopNavBar
        cases={cases}
        currentCaseId={currentCaseId}
        onSelectCase={(cid) => {
          setCurrentCaseId(cid);
          setSelectedRow(null);
        }}
        onDeleteCase={handleDeleteCase}
        activeTab={activeTab}
        onChangeTab={setActiveTab}
        onOpenNewCaseModal={() => setIsNewCaseModalOpen(true)}
        onOpenKeywordManager={() => setIsKeywordManagerOpen(true)}
        onOpenToolPaths={() => setIsToolPathsModalOpen(true)}
        onRefresh={handleRefresh}
        isRefreshing={isRefreshing}
        totalArtifacts={totalAllArtifactRows}
        totalTimeline={registryData?.timeline_total || 0}
        totalEvtx={totalEvtxCount}
        totalFileSystem={totalFileSystemCount}
        totalMalwareHits={totalMalwareHits}
        totalRegRipperPlugins={totalRegRipperPlugins}
        theme={theme}
        onToggleTheme={handleToggleTheme}
      />

      <GlobalFilterBar
        caseId={currentCaseId}
        filterState={globalFilterState}
        onFilterChange={setGlobalFilterState}
        onOpenKeywordManager={() => setIsKeywordManagerOpen(true)}
        artifacts={registryData?.artifacts}
        totalAllRows={totalAllArtifactRows}
        onSelectRegRipperPlugin={(pluginName) => {
          setSelectedRegRipperPlugin(pluginName);
          setActiveTab('regripper');
        }}
        selectedRegRipperPlugin={selectedRegRipperPlugin}
        onNavigateToRegRipper={() => setActiveTab('regripper')}
      />

      <main className="flex-1 flex overflow-hidden relative">
        {activeTab === 'dashboard' && (
          <div className="flex-1 h-full overflow-hidden">
            <CaseDashboard
              caseId={currentCaseId}
              onExploreArtifact={handleExploreCategory}
              onGoToTimeline={() => setActiveTab('timeline')}
              onGoToEventLogs={() => setActiveTab('eventlogs')}
              onGoToMalware={() => setActiveTab('malware')}
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
                globalSearch={globalFilterState.search}
                externalKeywords={globalFilterState.keywords}
                dateRange={globalFilterState.dateRange}
                tags={globalFilterState.tags}
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
              onBookmarkCreated={handleRefresh}
            />
          </div>
        )}

        {activeTab === 'regripper' && (
          <div className="flex-1 h-full overflow-hidden">
            <RegRipperExplorer
              caseId={currentCaseId}
              selectedPluginName={selectedRegRipperPlugin}
              onSelectPlugin={setSelectedRegRipperPlugin}
            />
          </div>
        )}

        {activeTab === 'eventlogs' && (
          <div className="flex-1 h-full overflow-hidden">
            <EventLogsWorkbench caseId={currentCaseId} />
          </div>
        )}

        {activeTab === 'filesystem' && (
          <div className="flex-1 h-full overflow-hidden">
            <FileSystemView caseId={currentCaseId} />
          </div>
        )}

        {activeTab === 'malware' && (
          <div className="flex-1 h-full overflow-hidden">
            <MalwareWorkbench caseId={currentCaseId} />
          </div>
        )}

        {activeTab === 'timeline' && (
          <div className="flex-1 h-full overflow-hidden">
            <TimelineExplorer
              caseId={currentCaseId}
              globalSearch={globalFilterState.search}
              dateRange={globalFilterState.dateRange}
            />
          </div>
        )}

        {activeTab === 'process' && (
          <div className="flex-1 h-full overflow-hidden">
            <ProcessWizard
              currentCaseId={currentCaseId}
              onCaseCreated={handleCaseCreated}
              isOpenAsModal={false}
              onNavigateToExamine={() => setActiveTab('artifacts')}
            />
          </div>
        )}
      </main>

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
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded-lg max-w-7xl w-full max-h-[92vh] overflow-hidden shadow-2xl flex flex-col text-[#0f172a] dark:text-[#f8fafc]">
            <ProcessWizard
              currentCaseId={currentCaseId}
              onCaseCreated={(newCid) => {
                handleCaseCreated(newCid);
              }}
              isOpenAsModal={true}
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