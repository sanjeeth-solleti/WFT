import React, { useState, useRef, useEffect } from 'react';
import {
  LayoutDashboard,
  Layers,
  Clock,
  Terminal,
  PlusCircle,
  RefreshCw,
  HardDrive,
  Hash,
  Sun,
  Moon,
  Database,
  Cpu,
  Activity,
  ShieldAlert,
  Settings,
  ChevronDown,
  Check,
  FolderTree,
  Trash2,
} from 'lucide-react';
import { CaseSummary, apiClient } from '../api/client';

export type TabType =
  | 'dashboard'
  | 'artifacts'
  | 'regripper'
  | 'eventlogs'
  | 'filesystem'
  | 'malware'
  | 'timeline'
  | 'process';

interface TopNavBarProps {
  cases: CaseSummary[];
  currentCaseId: string;
  onSelectCase: (caseId: string) => void;
  onDeleteCase?: (caseId: string) => Promise<void> | void;
  activeTab: TabType;
  onChangeTab: (tab: TabType) => void;
  onOpenNewCaseModal: () => void;
  onOpenKeywordManager: () => void;
  onOpenToolPaths: () => void;
  onRefresh: () => void;
  isRefreshing?: boolean;
  totalArtifacts?: number;
  totalTimeline?: number;
  totalEvtx?: number;
  totalFileSystem?: number;
  totalMalwareHits?: number;
  totalRegRipperPlugins?: number;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
}

export const TopNavBar: React.FC<TopNavBarProps> = ({
  cases,
  currentCaseId,
  onSelectCase,
  onDeleteCase,
  activeTab,
  onChangeTab,
  onOpenNewCaseModal,
  onOpenKeywordManager,
  onOpenToolPaths,
  onRefresh,
  isRefreshing = false,
  totalArtifacts = 0,
  totalTimeline = 0,
  totalEvtx = 0,
  totalFileSystem = 0,
  totalMalwareHits = 0,
  totalRegRipperPlugins = 0,
  theme,
  onToggleTheme,
}) => {
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const [isDeletingCase, setIsDeletingCase] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const handleDeleteCase = async () => {
    if (!currentCaseId || isDeletingCase) return;
    const confirmMsg = `Are you sure you want to permanently delete case "${currentCaseId}"?\n\nThis will remove all staged files, database tables, and audit logs.`;
    if (!window.confirm(confirmMsg)) return;

    setIsDeletingCase(true);
    try {
      if (onDeleteCase) {
        await onDeleteCase(currentCaseId);
      } else {
        await apiClient.deleteCase(currentCaseId);
        onRefresh();
      }
    } catch (err: any) {
      console.error('Failed to delete case:', err);
      alert(`Failed to delete case: ${err?.message || err}`);
    } finally {
      setIsDeletingCase(false);
    }
  };

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const VIEW_ITEMS: {
    id: TabType;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: number;
    badgeColor?: string;
    description: string;
  }[] = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: LayoutDashboard,
      description: 'Case overview & starting points',
    },
    {
      id: 'artifacts',
      label: 'Artifacts',
      icon: Layers,
      badge: totalArtifacts,
      badgeColor: 'bg-sky-100 text-sky-800 dark:bg-sky-950/60 dark:text-sky-300 border-sky-300 dark:border-sky-800',
      description: 'Virtualized evidence grids & categories',
    },
    {
      id: 'regripper',
      label: 'RegRipper',
      icon: Cpu,
      badge: totalRegRipperPlugins,
      badgeColor: 'bg-purple-100 text-purple-700 dark:bg-purple-950/60 dark:text-purple-300 border-purple-200 dark:border-purple-800',
      description: 'Registry hive fast analysis & plugins',
    },
    {
      id: 'eventlogs',
      label: 'Event Logs',
      icon: Activity,
      badge: totalEvtx,
      badgeColor: 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300 border-amber-300 dark:border-amber-800',
      description: 'DFIR Event Logs Workbench',
    },
    {
      id: 'filesystem',
      label: 'File System',
      icon: FolderTree,
      badge: totalFileSystem,
      badgeColor: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800',
      description: 'FTK Imager-style file explorer & NTFS inspection',
    },
    {
      id: 'malware',
      label: 'Malware & Stinger',
      icon: ShieldAlert,
      badge: totalMalwareHits,
      badgeColor: 'bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300 border-rose-300 dark:border-rose-800',
      description: 'Trellix Stinger AV & YARA-X scanning',
    },
    {
      id: 'timeline',
      label: 'Timeline',
      icon: Clock,
      badge: totalTimeline,
      badgeColor: 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-600',
      description: 'Unified super-timeline chronological explorer',
    },
    {
      id: 'process',
      label: 'Console / Logs',
      icon: Terminal,
      description: 'Real-time processing audit & job console',
    },
  ];

  const activeView = VIEW_ITEMS.find((v) => v.id === activeTab) || VIEW_ITEMS[0];
  const ActiveIcon = activeView.icon;

  return (
    <header className="h-11 bg-white dark:bg-[#1e293b] border-b border-[#cbd5e1] dark:border-[#334155] px-3 flex items-center justify-between gap-2 select-none z-30 shadow-xs font-sans w-full min-w-0 shrink-0">
      {/* Brand & Case Selector */}
      <div className="flex items-center gap-2.5 shrink-0 min-w-0">
        {/* Brand */}
        <div className="flex items-center gap-2 pr-2.5 border-r border-[#cbd5e1] dark:border-[#334155] shrink-0" title="Windows Forensic Toolkit (WFT)">
          <div className="w-8 h-6 rounded bg-[#0284c7] dark:bg-[#0369a1] flex items-center justify-center text-white font-black tracking-wider text-[10px] border border-[#0369a1] dark:border-[#0284c7] shrink-0">
            WFT
          </div>
          <span className="font-extrabold text-xs tracking-wide text-[#0f172a] dark:text-[#f8fafc] flex items-center gap-1.5 leading-none shrink-0">
            <span className="hidden sm:inline">WINDOWS FORENSIC TOOLKIT</span>
            <span className="sm:hidden">WFT</span>
            <span className="text-[9.5px] font-mono font-bold px-1.5 py-0.5 rounded bg-slate-100 dark:bg-[#0f172a] text-[#0284c7] dark:text-[#38bdf8] border border-[#cbd5e1] dark:border-[#334155]">
              EXAMINE
            </span>
          </span>
        </div>

        {/* Case Selector Dropdown & Actions */}
        <div className="flex items-center gap-1.5 shrink-0">
          <div className="relative">
            <HardDrive className="w-3.5 h-3.5 absolute left-2 top-2 text-slate-400 pointer-events-none" />
            <select
              aria-label="Active Evidence Case"
              value={currentCaseId}
              onChange={(e) => onSelectCase(e.target.value)}
              className="bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] hover:border-slate-400 focus:border-[#0284c7] text-[#0f172a] dark:text-[#f8fafc] text-xs rounded pl-7 pr-6 py-1 focus:outline-none focus:ring-1 focus:ring-[#0284c7] font-mono transition-colors shadow-2xs max-w-[170px] truncate"
            >
              {cases.length === 0 ? (
                <option value="">No Cases</option>
              ) : (
                cases.map((c) => (
                  <option key={c.case_id} value={c.case_id}>
                    {c.case_id} ({c.total_artifact_rows.toLocaleString()} rows)
                  </option>
                ))
              )}
            </select>
          </div>

          {/* Delete Case (1-Click Red Trash Icon Button) */}
          {currentCaseId && (
            <button
              onClick={handleDeleteCase}
              disabled={isDeletingCase}
              className={`p-1.5 rounded border border-rose-300 dark:border-rose-900 bg-rose-50 hover:bg-rose-100 dark:bg-rose-950/40 dark:hover:bg-rose-900/60 text-rose-600 dark:text-rose-400 transition-colors cursor-pointer shrink-0 shadow-2xs ${
                isDeletingCase ? 'opacity-50 cursor-not-allowed animate-pulse' : ''
              }`}
              title={`Permanently Delete Case "${currentCaseId}"`}
              aria-label={`Delete Case ${currentCaseId}`}
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}

          <button
            onClick={onOpenNewCaseModal}
            className="flex items-center gap-1 px-2.5 py-1 bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-semibold rounded border border-[#0369a1] shadow-2xs transition-colors cursor-pointer shrink-0"
            title="Create New Case / Process Evidence"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            <span>Process</span>
          </button>

          <button
            onClick={onOpenKeywordManager}
            className="flex items-center gap-1 px-2 py-1 bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] text-[#0f172a] dark:text-[#f8fafc] border border-[#cbd5e1] dark:border-[#334155] text-xs font-semibold rounded shadow-2xs transition-colors cursor-pointer shrink-0"
            title="Manage Case Keyword Lists & IOCs"
          >
            <Hash className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
            <span>Keywords</span>
          </button>

          <button
            onClick={onOpenToolPaths}
            className="flex items-center gap-1 px-2 py-1 bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] text-[#0f172a] dark:text-[#f8fafc] border border-[#cbd5e1] dark:border-[#334155] text-xs font-semibold rounded shadow-2xs transition-colors cursor-pointer shrink-0"
            title="Configure External Tool Paths & Environment"
          >
            <Settings className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
            <span>Tool Paths</span>
          </button>

          <button
            onClick={onRefresh}
            className={`p-1 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] text-slate-600 dark:text-slate-300 transition-colors cursor-pointer shrink-0 ${
              isRefreshing ? 'animate-spin text-[#0284c7]' : ''
            }`}
            title="Refresh Case Data"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* View Selector Dropdown (Prevents any horizontal overflow or clipping) */}
      <div className="relative shrink-0" ref={dropdownRef}>
        <button
          onClick={() => setIsDropdownOpen((prev) => !prev)}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-md border text-xs font-semibold shadow-2xs transition-all cursor-pointer ${
            isDropdownOpen
              ? 'bg-sky-50 dark:bg-[#0c4a6e]/40 border-[#0284c7] dark:border-[#38bdf8] text-[#0284c7] dark:text-[#38bdf8]'
              : 'bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#1e293b] border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc]'
          }`}
          title="Select Active Forensic View"
          aria-haspopup="true"
          aria-expanded={isDropdownOpen}
        >
          <ActiveIcon className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />
          <span className="font-bold text-xs tracking-tight">{activeView.label}</span>
          {activeView.badge !== undefined && activeView.badge > 0 && (
            <span
              className={`px-1.5 py-0.2 text-[10px] rounded font-mono font-bold border ${activeView.badgeColor}`}
            >
              {activeView.badge.toLocaleString()}
            </span>
          )}
          <ChevronDown
            className={`w-3.5 h-3.5 text-slate-400 transition-transform duration-200 shrink-0 ${
              isDropdownOpen ? 'rotate-180 text-[#0284c7] dark:text-[#38bdf8]' : ''
            }`}
          />
        </button>

        {/* Dropdown Menu */}
        {isDropdownOpen && (
          <div className="absolute left-0 mt-1 w-72 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded-lg shadow-xl z-50 overflow-hidden py-1 animate-in fade-in duration-150">
            <div className="px-3 py-1.5 border-b border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a]">
              <span className="text-[10px] font-extrabold uppercase tracking-wider text-slate-400">
                FORENSIC VIEWS
              </span>
            </div>
            <div className="py-1">
              {VIEW_ITEMS.map((item) => {
                const ItemIcon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      onChangeTab(item.id);
                      setIsDropdownOpen(false);
                    }}
                    className={`w-full text-left px-3 py-2 flex items-center justify-between gap-2.5 transition-colors cursor-pointer text-xs ${
                      isActive
                        ? 'bg-sky-50 dark:bg-[#0c4a6e]/50 text-[#0284c7] dark:text-[#38bdf8] font-bold'
                        : 'hover:bg-slate-100 dark:hover:bg-[#0f172a] text-[#0f172a] dark:text-[#f8fafc]'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <div
                        className={`p-1 rounded shrink-0 ${
                          isActive
                            ? 'bg-[#0284c7] text-white'
                            : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400'
                        }`}
                      >
                        <ItemIcon className="w-3.5 h-3.5" />
                      </div>
                      <div className="truncate">
                        <div className="leading-tight">{item.label}</div>
                        <div className="text-[10px] text-slate-400 dark:text-slate-400 font-normal truncate">
                          {item.description}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      {item.badge !== undefined && item.badge > 0 && (
                        <span
                          className={`px-1.5 py-0.2 text-[10px] rounded font-mono font-bold border ${item.badgeColor}`}
                        >
                          {item.badge.toLocaleString()}
                        </span>
                      )}
                      {isActive && <Check className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Right Controls: Stats + Theme Switcher (Locked with shrink-0 ml-auto) */}
      <div className="shrink-0 ml-auto flex items-center gap-2">
        {/* Quick Stats Badges: visible on large screens */}
        <div className="hidden 2xl:flex items-center gap-2 pr-2 border-r border-[#cbd5e1] dark:border-[#334155] text-xs text-slate-500 dark:text-slate-400 font-mono">
          <div className="flex items-center gap-1" title="Total Evidence Rows">
            <Database className="w-3 h-3 text-[#0284c7] dark:text-[#38bdf8]" />
            <span className="font-semibold text-[#0f172a] dark:text-[#f8fafc]">
              {totalArtifacts.toLocaleString()}
            </span>
          </div>
        </div>

        {/* Theme Toggle Button: Always visible on every screen */}
        <button
          onClick={onToggleTheme}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#f1f5f9] hover:bg-slate-200 dark:bg-[#0f172a] dark:hover:bg-[#334155] text-[#0f172a] dark:text-[#f8fafc] text-xs font-semibold border border-[#cbd5e1] dark:border-[#334155] shadow-2xs transition-colors cursor-pointer shrink-0"
          title={`Switch to ${theme === 'light' ? 'Dark' : 'Light'} theme`}
          aria-label={`Switch to ${theme === 'light' ? 'Dark' : 'Light'} theme`}
        >
          {theme === 'light' ? (
            <>
              <Sun className="w-3.5 h-3.5 text-amber-500 shrink-0" />
              <span className="font-semibold text-xs">Light</span>
            </>
          ) : (
            <>
              <Moon className="w-3.5 h-3.5 text-sky-400 shrink-0" />
              <span className="font-semibold text-xs">Dark</span>
            </>
          )}
        </button>
      </div>
    </header>
  );
};
