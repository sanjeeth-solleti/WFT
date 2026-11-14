import React, { useState, useEffect, useRef } from 'react';
import {
  Search,
  Calendar,
  Layers,
  Hash,
  Tag,
  FileType,
  ChevronDown,
  X,
  Check,
  RotateCcw,
  ExternalLink,
  Loader2,
  CalendarRange,
  Cpu,
} from 'lucide-react';
import { apiClient, CaseKeyword, ArtifactItem, RegRipperPluginItem } from '../api/client';

export interface GlobalFilterState {
  evidenceSource?: string;
  artifactTable?: string;
  contentTypes: string[];
  dateRange: {
    preset: string;
    startUtc?: string;
    endUtc?: string;
  };
  keywords: string[];
  tags: string[];
  search: string;
}

interface GlobalFilterBarProps {
  caseId: string;
  filterState: GlobalFilterState;
  onFilterChange: (newState: GlobalFilterState) => void;
  onOpenKeywordManager: () => void;
  artifacts?: ArtifactItem[];
  totalAllRows?: number;
  onSelectRegRipperPlugin?: (pluginName: string) => void;
  selectedRegRipperPlugin?: string | null;
  onNavigateToRegRipper?: () => void;
}

// Content Types catalog
export const CONTENT_TYPES = [
  { id: 'executables', label: 'Executables & Binaries (.exe, .dll, Prefetch, ShimCache)' },
  { id: 'documents', label: 'Documents & Office (.pdf, .docx, LNK, JumpLists)' },
  { id: 'web', label: 'Web & URLs (Chrome, Edge, Firefox History)' },
  { id: 'chat_mail', label: 'Communications (Teams, Discord, Outlook)' },
  { id: 'system', label: 'System & Registry (EVTX, Registry, USB, SRUM)' },
  { id: 'media', label: 'Media & Carved Images (JPEG, PNG, OCR)' },
] as const;

// Helper to check whether an artifact matches selected content types
export function matchContentType(artifact: ArtifactItem, types: string[]): boolean {
  if (!types || types.length === 0) return true;
  const cat = (artifact.category || '').toUpperCase();
  const name = `${artifact.display_name || ''} ${artifact.table_name || ''}`.toUpperCase();

  for (const t of types) {
    if (t === 'executables') {
      if (
        cat.includes('PROGRAM EXECUTION') ||
        cat.includes('MALWARE') ||
        name.includes('PREFETCH') ||
        name.includes('SHIMCACHE') ||
        name.includes('AMCACHE') ||
        name.includes('PECMD') ||
        name.includes('ACTIVITY')
      ) return true;
    }
    if (t === 'documents') {
      if (
        cat.includes('DOCUMENTS') ||
        cat.includes('FILE SYSTEM') ||
        name.includes('LNK') ||
        name.includes('JUMPLIST') ||
        name.includes('SHELLBAG') ||
        name.includes('MFT')
      ) return true;
    }
    if (t === 'web') {
      if (
        cat.includes('WEB') ||
        cat.includes('BROWSER') ||
        name.includes('CHROME') ||
        name.includes('EDGE') ||
        name.includes('FIREFOX') ||
        name.includes('HISTORY') ||
        name.includes('DOWNLOAD') ||
        name.includes('LOGIN')
      ) return true;
    }
    if (t === 'chat_mail') {
      if (
        cat.includes('CHAT') ||
        cat.includes('EMAIL') ||
        cat.includes('COMMUNICATION') ||
        name.includes('TEAMS') ||
        name.includes('DISCORD') ||
        name.includes('SLACK') ||
        name.includes('MAIL')
      ) return true;
    }
    if (t === 'system') {
      if (
        cat.includes('EVENT') ||
        cat.includes('REGISTRY') ||
        cat.includes('NETWORK') ||
        cat.includes('USB') ||
        cat.includes('OPERATING SYSTEM') ||
        name.includes('EVTX') ||
        name.includes('RECMD') ||
        name.includes('SRUM') ||
        name.includes('USB')
      ) return true;
    }
    if (t === 'media') {
      if (
        cat.includes('MEDIA') ||
        cat.includes('OCR') ||
        name.includes('IMAGE') ||
        name.includes('THUMBCACHE') ||
        name.includes('EXIF') ||
        name.includes('ENRICHMENT')
      ) return true;
    }
  }
  return false;
}

// Forensic Bookmark & Tag Options (Classic Enterprise Flat Palette)
export const TAG_OPTIONS = [
  { id: 'Key Evidence', label: 'Key Evidence', color: 'bg-slate-100 text-[#0284c7] border-[#cbd5e1] dark:bg-slate-800 dark:text-[#38bdf8] dark:border-slate-700' },
  { id: 'Malware', label: 'Malware', color: 'bg-red-50 text-[#991b1b] border-red-300 dark:bg-red-950/60 dark:text-red-300 dark:border-red-800' },
  { id: 'Initial Access', label: 'Initial Access', color: 'bg-slate-100 text-slate-800 border-[#cbd5e1] dark:bg-slate-800 dark:text-slate-200 dark:border-slate-700' },
  { id: 'Persistence', label: 'Persistence', color: 'bg-slate-100 text-slate-800 border-[#cbd5e1] dark:bg-slate-800 dark:text-slate-200 dark:border-slate-700' },
  { id: 'Lateral Movement', label: 'Lateral Movement', color: 'bg-slate-100 text-slate-800 border-[#cbd5e1] dark:bg-slate-800 dark:text-slate-200 dark:border-slate-700' },
  { id: 'Exfiltration', label: 'Exfiltration', color: 'bg-slate-100 text-slate-800 border-[#cbd5e1] dark:bg-slate-800 dark:text-slate-200 dark:border-slate-700' },
];

export const GlobalFilterBar: React.FC<GlobalFilterBarProps> = ({
  caseId,
  filterState,
  onFilterChange,
  onOpenKeywordManager,
  artifacts = [],
  totalAllRows = 0,
  onSelectRegRipperPlugin,
  selectedRegRipperPlugin,
  onNavigateToRegRipper,
}) => {
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [dropdownPos, setDropdownPos] = useState<{ top: number; left: number } | null>(null);
  const [caseKeywords, setCaseKeywords] = useState<CaseKeyword[]>([]);
  const [isLoadingKeywords, setIsLoadingKeywords] = useState(false);
  const [artifactSearch, setArtifactSearch] = useState('');

  // RegRipper dropdown state
  const [regripperPlugins, setRegripperPlugins] = useState<RegRipperPluginItem[]>([]);
  const [isLoadingRegripper, setIsLoadingRegripper] = useState<boolean>(false);
  const [regripperSearch, setRegripperSearch] = useState<string>('');
  const [regripperHive, setRegripperHive] = useState<string>('ALL');

  // Custom date picker state
  const [customStart, setCustomStart] = useState<string>('');
  const [customEnd, setCustomEnd] = useState<string>('');

  const barRef = useRef<HTMLDivElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click or Escape
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      const target = e.target as Node;
      if (
        barRef.current &&
        !barRef.current.contains(target) &&
        popoverRef.current &&
        !popoverRef.current.contains(target)
      ) {
        setActiveDropdown(null);
        setDropdownPos(null);
      }
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setActiveDropdown(null);
        setDropdownPos(null);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  // Fetch keywords when keyword dropdown is opened or case changes
  useEffect(() => {
    if (caseId && (activeDropdown === 'keywords' || caseKeywords.length === 0)) {
      setIsLoadingKeywords(true);
      apiClient
        .listKeywords(caseId)
        .then((res) => {
          setCaseKeywords(res.keywords || []);
        })
        .catch(() => {
          setCaseKeywords([]);
        })
        .finally(() => {
          setIsLoadingKeywords(false);
        });
    }
  }, [caseId, activeDropdown]);

  // Fetch RegRipper plugins when dropdown is opened or case changes
  useEffect(() => {
    if (caseId && (activeDropdown === 'regripper' || regripperPlugins.length === 0)) {
      setIsLoadingRegripper(true);
      apiClient
        .getRegRipperPlugins(caseId)
        .then((res) => {
          setRegripperPlugins(res.plugins || []);
        })
        .catch((err) => {
          console.error('Failed to load RegRipper plugins for filter bar:', err);
        })
        .finally(() => {
          setIsLoadingRegripper(false);
        });
    }
  }, [caseId, activeDropdown]);

  // Filtered RegRipper plugins for popover
  const filteredRegRipperPlugins = React.useMemo(() => {
    return regripperPlugins.filter((p) => {
      if (regripperHive !== 'ALL') {
        const h = (p.hive_type || '').toUpperCase();
        if (!h.includes(regripperHive)) return false;
      }
      if (regripperSearch.trim()) {
        const q = regripperSearch.toLowerCase();
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
  }, [regripperPlugins, regripperHive, regripperSearch]);

  const toggleDropdown = (name: string, event: React.MouseEvent<HTMLButtonElement>, width = 280) => {
    if (activeDropdown === name) {
      setActiveDropdown(null);
      setDropdownPos(null);
    } else {
      const rect = event.currentTarget.getBoundingClientRect();
      const left = Math.max(8, Math.min(rect.left, window.innerWidth - width - 16));
      setDropdownPos({
        top: rect.bottom + 4,
        left,
      });
      setActiveDropdown(name);
    }
  };

  // Count active filters
  const activeCount =
    (filterState.artifactTable ? 1 : 0) +
    filterState.contentTypes.length +
    (filterState.dateRange.preset !== 'all' ? 1 : 0) +
    filterState.keywords.length +
    filterState.tags.length;

  const handleClearAll = () => {
    onFilterChange({
      evidenceSource: undefined,
      artifactTable: undefined,
      contentTypes: [],
      dateRange: { preset: 'all' },
      keywords: [],
      tags: [],
      search: '',
    });
    setActiveDropdown(null);
    setDropdownPos(null);
  };

  const toggleContentType = (typeId: string) => {
    const next = filterState.contentTypes.includes(typeId)
      ? filterState.contentTypes.filter((t) => t !== typeId)
      : [...filterState.contentTypes, typeId];
    onFilterChange({ ...filterState, contentTypes: next });
  };

  const handleSelectAllContentTypes = () => {
    onFilterChange({ ...filterState, contentTypes: CONTENT_TYPES.map((c) => c.id) });
  };

  const handleClearContentTypes = () => {
    onFilterChange({ ...filterState, contentTypes: [] });
  };

  const toggleKeyword = (kw: string) => {
    const next = filterState.keywords.includes(kw)
      ? filterState.keywords.filter((k) => k !== kw)
      : [...filterState.keywords, kw];
    onFilterChange({ ...filterState, keywords: next });
  };

  const handleSelectAllKeywords = () => {
    onFilterChange({ ...filterState, keywords: caseKeywords.map((k) => k.keyword) });
  };

  const handleClearKeywords = () => {
    onFilterChange({ ...filterState, keywords: [] });
  };

  const toggleTag = (tag: string) => {
    const next = filterState.tags.includes(tag)
      ? filterState.tags.filter((t) => t !== tag)
      : [...filterState.tags, tag];
    onFilterChange({ ...filterState, tags: next });
  };

  const handleSelectAllTags = () => {
    onFilterChange({ ...filterState, tags: TAG_OPTIONS.map((t) => t.id) });
  };

  const handleClearTags = () => {
    onFilterChange({ ...filterState, tags: [] });
  };

  const setDatePreset = (preset: string) => {
    const now = new Date();
    let start: string | undefined;
    if (preset === '24h') {
      const d = new Date(now.getTime() - 24 * 3600 * 1000);
      start = d.toISOString();
    } else if (preset === '7d') {
      const d = new Date(now.getTime() - 7 * 24 * 3600 * 1000);
      start = d.toISOString();
    } else if (preset === '30d') {
      const d = new Date(now.getTime() - 30 * 24 * 3600 * 1000);
      start = d.toISOString();
    }
    onFilterChange({
      ...filterState,
      dateRange: { preset, startUtc: start, endUtc: undefined },
    });
    setActiveDropdown(null);
    setDropdownPos(null);
  };

  const applyCustomDateRange = () => {
    if (!customStart && !customEnd) return;
    const startUtc = customStart ? new Date(customStart).toISOString() : undefined;
    const endUtc = customEnd ? new Date(customEnd).toISOString() : undefined;
    onFilterChange({
      ...filterState,
      dateRange: {
        preset: 'custom',
        startUtc,
        endUtc,
      },
    });
    setActiveDropdown(null);
    setDropdownPos(null);
  };

  // Find human-readable label for selected artifact
  const selectedArtifactItem = artifacts.find((a) => a.table_name === filterState.artifactTable);
  const artifactButtonLabel = selectedArtifactItem
    ? selectedArtifactItem.display_name
    : filterState.artifactTable || 'Artifacts';

  return (
    <>
      <div
        ref={barRef}
        className="h-11 bg-white dark:bg-[#1e293b] border-b border-[#cbd5e1] dark:border-[#334155] px-4 flex items-center justify-between select-none z-20 shrink-0 font-sans shadow-2xs relative"
      >
        {/* Left: Filter Dropdown Pills */}
        <div className="flex items-center gap-2 overflow-visible py-1 shrink-0">
          {/* 1. Artifacts ▾ */}
          <button
            onClick={(e) => toggleDropdown('artifacts', e, 320)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border transition-colors cursor-pointer ${
              filterState.artifactTable
                ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] border-[#0284c7] text-[#0369a1] dark:text-[#38bdf8] font-semibold'
                : 'bg-white dark:bg-[#0f172a] hover:bg-slate-50 dark:hover:bg-[#334155] border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc]'
            }`}
          >
            <Layers className="w-3 h-3 text-slate-500" />
            <span className="max-w-[140px] truncate" title={artifactButtonLabel}>
              {artifactButtonLabel}
            </span>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {/* 2b. RegRipper ▾ */}
          <button
            onClick={(e) => toggleDropdown('regripper', e, 380)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border transition-colors cursor-pointer ${
              selectedRegRipperPlugin
                ? 'bg-purple-100 dark:bg-purple-950/70 border-purple-500 text-purple-800 dark:text-purple-300 font-semibold'
                : 'bg-white dark:bg-[#0f172a] hover:bg-slate-50 dark:hover:bg-[#334155] border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc]'
            }`}
          >
            <Cpu className="w-3 h-3 text-purple-600 dark:text-purple-400" />
            <span
              className="max-w-[140px] truncate"
              title={selectedRegRipperPlugin ? `RegRipper: ${selectedRegRipperPlugin}` : 'RegRipper'}
            >
              {selectedRegRipperPlugin ? `RegRipper: ${selectedRegRipperPlugin}` : 'RegRipper'}
              {regripperPlugins.length > 0 && !selectedRegRipperPlugin ? ` (${regripperPlugins.length})` : ''}
            </span>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {/* 3. Content types ▾ */}
          <button
            onClick={(e) => toggleDropdown('content', e, 320)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border transition-colors cursor-pointer ${
              filterState.contentTypes.length > 0
                ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] border-[#0284c7] text-[#0369a1] dark:text-[#38bdf8] font-semibold'
                : 'bg-white dark:bg-[#0f172a] hover:bg-slate-50 dark:hover:bg-[#334155] border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc]'
            }`}
          >
            <FileType className="w-3 h-3 text-slate-500" />
            <span>
              Content types
              {filterState.contentTypes.length > 0 ? ` (${filterState.contentTypes.length})` : ''}
            </span>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {/* 4. Date & Time ▾ */}
          <button
            onClick={(e) => toggleDropdown('date', e, 280)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border transition-colors cursor-pointer ${
              filterState.dateRange.preset !== 'all'
                ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] border-[#0284c7] text-[#0369a1] dark:text-[#38bdf8] font-semibold'
                : 'bg-white dark:bg-[#0f172a] hover:bg-slate-50 dark:hover:bg-[#334155] border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc]'
            }`}
          >
            <Calendar className="w-3 h-3 text-slate-500" />
            <span>
              {filterState.dateRange.preset === 'all'
                ? 'Date & Time'
                : filterState.dateRange.preset === 'custom'
                ? 'Date: Custom'
                : `Date: ${filterState.dateRange.preset}`}
            </span>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {/* 5. Keyword lists ▾ */}
          <button
            onClick={(e) => toggleDropdown('keywords', e, 300)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border transition-colors cursor-pointer ${
              filterState.keywords.length > 0
                ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] border-[#0284c7] text-[#0369a1] dark:text-[#38bdf8] font-semibold'
                : 'bg-white dark:bg-[#0f172a] hover:bg-slate-50 dark:hover:bg-[#334155] border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc]'
            }`}
          >
            <Hash className="w-3 h-3 text-slate-500" />
            <span>
              Keyword lists
              {filterState.keywords.length > 0 ? ` (${filterState.keywords.length})` : ''}
            </span>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {/* 6. Tags & Bookmarks ▾ */}
          <button
            onClick={(e) => toggleDropdown('tags', e, 280)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border transition-colors cursor-pointer ${
              filterState.tags.length > 0
                ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] border-[#0284c7] text-[#0369a1] dark:text-[#38bdf8] font-semibold'
                : 'bg-white dark:bg-[#0f172a] hover:bg-slate-50 dark:hover:bg-[#334155] border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc]'
            }`}
          >
            <Tag className="w-3 h-3 text-slate-500" />
            <span>
              Tags & Bookmarks
              {filterState.tags.length > 0 ? ` (${filterState.tags.length})` : ''}
            </span>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {/* Clear All Filters Button */}
          {activeCount > 0 && (
            <button
              onClick={handleClearAll}
              className="flex items-center gap-1 px-2.5 py-1 rounded text-xs text-[#991b1b] dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-950/40 font-semibold transition-colors cursor-pointer shrink-0 ml-1"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Clear filters</span>
            </button>
          )}
        </div>

        {/* Right: Global Search Bar */}
        <div className="relative w-64 md:w-80 shrink-0">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400 pointer-events-none" />
          <input
            type="text"
            value={filterState.search}
            onChange={(e) => onFilterChange({ ...filterState, search: e.target.value })}
            placeholder="Global search evidence, hashes, paths..."
            className="w-full bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] focus:border-[#0284c7] rounded pl-9 pr-7 py-1 text-xs text-[#0f172a] dark:text-[#f8fafc] placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-[#0284c7] font-sans shadow-2xs"
          />
          {filterState.search && (
            <button
              onClick={() => onFilterChange({ ...filterState, search: '' })}
              className="absolute right-2.5 top-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
              title="Clear search"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* FLOATING DROPDOWN POPOVERS - Positioned fixed below trigger to prevent any clipping */}
      {activeDropdown && dropdownPos && (
        <div
          ref={popoverRef}
          style={{
            position: 'fixed',
            top: dropdownPos.top,
            left: dropdownPos.left,
            zIndex: 9999,
          }}
          className="bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded-md shadow-2xl p-2 font-sans text-xs animate-in fade-in zoom-in-95 duration-150"
        >
          {/* 1. Artifacts Popover */}
          {activeDropdown === 'artifacts' && (
            <div className="w-80">
              <div className="px-2 py-1 border-b border-[#cbd5e1] dark:border-[#334155] mb-2 flex items-center justify-between">
                <span className="text-[11px] font-bold uppercase text-slate-500">
                  Select Artifact Table
                </span>
                <span className="text-[10px] font-mono text-slate-400">
                  {artifacts.length} available
                </span>
              </div>
              <div className="px-1 mb-2">
                <div className="relative">
                  <Search className="w-3 h-3 absolute left-2.5 top-2 text-slate-400" />
                  <input
                    type="text"
                    value={artifactSearch}
                    onChange={(e) => setArtifactSearch(e.target.value)}
                    placeholder="Search artifacts..."
                    autoFocus
                    className="w-full bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded pl-7 pr-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-[#0284c7]"
                  />
                </div>
              </div>

              <div className="max-h-64 overflow-y-auto space-y-0.5 pr-1">
                <button
                  onClick={() => {
                    onFilterChange({ ...filterState, artifactTable: undefined });
                    setActiveDropdown(null);
                    setDropdownPos(null);
                  }}
                  className={`w-full text-left px-2 py-1.5 rounded text-xs flex items-center justify-between font-bold cursor-pointer transition-colors ${
                    !filterState.artifactTable
                      ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0369a1] dark:text-[#38bdf8]'
                      : 'hover:bg-slate-100 dark:hover:bg-[#334155]'
                  }`}
                >
                  <div className="flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
                    <span>(Show All Evidence / All Artifacts)</span>
                  </div>
                  <span className="font-mono text-[10px] text-slate-500">
                    ({totalAllRows.toLocaleString()})
                  </span>
                </button>

                {artifacts
                  .filter(
                    (a) =>
                      !artifactSearch ||
                      a.display_name.toLowerCase().includes(artifactSearch.toLowerCase()) ||
                      a.category.toLowerCase().includes(artifactSearch.toLowerCase()) ||
                      a.table_name.toLowerCase().includes(artifactSearch.toLowerCase())
                  )
                  .map((a) => {
                    const isSelected = filterState.artifactTable === a.table_name;
                    return (
                      <button
                        key={a.artifact_id}
                        onClick={() => {
                          onFilterChange({ ...filterState, artifactTable: a.table_name });
                          setActiveDropdown(null);
                          setDropdownPos(null);
                        }}
                        className={`w-full text-left px-2 py-1.5 rounded text-xs flex items-center justify-between cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0369a1] dark:text-[#38bdf8] font-bold'
                            : 'hover:bg-slate-100 dark:hover:bg-[#334155]'
                        }`}
                      >
                        <div className="flex items-center gap-1.5 min-w-0 pr-2">
                          {isSelected ? (
                            <Check className="w-3 h-3 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />
                          ) : (
                            <span className="w-3 h-3 shrink-0" />
                          )}
                          <div className="min-w-0 truncate">
                            <span className="truncate block">{a.display_name}</span>
                            <span className="text-[10px] text-slate-400 font-mono block">
                              {a.category}
                            </span>
                          </div>
                        </div>
                        <span className="font-mono text-[10px] text-slate-500 shrink-0">
                          ({a.row_count.toLocaleString()})
                        </span>
                      </button>
                    );
                  })}
              </div>
            </div>
          )}

          {/* 2b. RegRipper Popover */}
          {activeDropdown === 'regripper' && (
            <div className="w-96">
              <div className="px-2 py-1 border-b border-[#cbd5e1] dark:border-[#334155] mb-2 flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
                  <span className="text-[11px] font-bold uppercase text-slate-700 dark:text-slate-300">
                    RegRipper Plugins
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-purple-600 dark:text-purple-400 font-bold">
                    {regripperPlugins.length} parsed
                  </span>
                  {onNavigateToRegRipper && (
                    <button
                      onClick={() => {
                        setActiveDropdown(null);
                        setDropdownPos(null);
                        onNavigateToRegRipper();
                      }}
                      className="text-[10px] font-semibold text-[#0284c7] hover:underline flex items-center gap-0.5 cursor-pointer"
                    >
                      <span>Open Tab</span>
                      <ExternalLink className="w-2.5 h-2.5" />
                    </button>
                  )}
                </div>
              </div>

              {/* Search input */}
              <div className="px-1 mb-2">
                <div className="relative">
                  <Search className="w-3 h-3 absolute left-2 top-2 text-slate-400" />
                  <input
                    type="text"
                    value={regripperSearch}
                    onChange={(e) => setRegripperSearch(e.target.value)}
                    placeholder="Search plugins, MITRE tags, descriptions..."
                    className="w-full bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded pl-7 pr-2 py-1 text-xs focus:outline-none focus:border-purple-500 font-sans"
                    autoFocus
                  />
                  {regripperSearch && (
                    <button
                      onClick={() => setRegripperSearch('')}
                      className="absolute right-2 top-1.5 text-slate-400 hover:text-slate-600"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  )}
                </div>
              </div>

              {/* Hive filter pills */}
              <div className="flex flex-wrap gap-1 px-1 mb-2">
                {['ALL', 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'NTUSER', 'USRCLASS', 'AMCACHE'].map((h) => (
                  <button
                    key={h}
                    onClick={() => setRegripperHive(h)}
                    className={`px-1.5 py-0.5 text-[9.5px] font-mono font-semibold rounded cursor-pointer transition-colors ${
                      regripperHive === h
                        ? 'bg-purple-600 text-white'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'
                    }`}
                  >
                    {h}
                  </button>
                ))}
              </div>

              {/* Plugin List */}
              <div className="max-h-64 overflow-y-auto space-y-1 pr-1 custom-scrollbar">
                {isLoadingRegripper ? (
                  <div className="p-4 text-center text-slate-400 flex items-center justify-center gap-1.5">
                    <Loader2 className="w-3.5 h-3.5 animate-spin text-purple-600" />
                    <span>Loading RegRipper plugins...</span>
                  </div>
                ) : filteredRegRipperPlugins.length === 0 ? (
                  <div className="p-4 text-center text-slate-400 text-xs">
                    No plugins match "{regripperSearch}"
                  </div>
                ) : (
                  filteredRegRipperPlugins.map((p) => {
                    const isSelected = selectedRegRipperPlugin === p.plugin_name;
                    return (
                      <button
                        key={`${p.hive_name}-${p.plugin_name}-${p._row_id}`}
                        onClick={() => {
                          if (onSelectRegRipperPlugin) {
                            onSelectRegRipperPlugin(p.plugin_name);
                          }
                          if (onNavigateToRegRipper) {
                            onNavigateToRegRipper();
                          }
                          setActiveDropdown(null);
                          setDropdownPos(null);
                        }}
                        className={`w-full text-left px-2 py-1.5 rounded text-xs flex items-center justify-between cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-purple-100 dark:bg-purple-950/70 text-purple-900 dark:text-purple-200 font-bold'
                            : 'hover:bg-slate-100 dark:hover:bg-[#334155]'
                        }`}
                      >
                        <div className="min-w-0 pr-2 flex-1">
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono font-semibold text-xs truncate">
                              {p.plugin_name}
                            </span>
                            <span className="text-[9px] font-mono px-1 rounded bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
                              {p.hive_type}
                            </span>
                            {p.mitre_attack && p.mitre_attack !== 'N/A' && (
                              <span className="text-[9px] font-mono px-1 rounded bg-rose-100 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800">
                                {p.mitre_attack}
                              </span>
                            )}
                          </div>
                          <div className="text-[10px] text-slate-500 dark:text-slate-400 truncate">
                            {p.description || p.summary_line || p.category}
                          </div>
                        </div>
                        <span className="font-mono text-[10px] text-purple-600 dark:text-purple-400 shrink-0 font-bold">
                          {p.output_lines_count} L
                        </span>
                      </button>
                    );
                  })
                )}
              </div>
            </div>
          )}

          {/* 3. Content Types Popover */}
          {activeDropdown === 'content' && (
            <div className="w-80">
              <div className="flex items-center justify-between px-2 py-1 border-b border-[#cbd5e1] dark:border-[#334155] mb-2">
                <span className="text-[11px] font-bold uppercase text-slate-500">
                  Filter by Content Type
                </span>
                <div className="flex items-center gap-2 text-[11px]">
                  <button
                    onClick={handleSelectAllContentTypes}
                    className="text-[#0284c7] hover:underline font-semibold cursor-pointer"
                  >
                    Select All
                  </button>
                  <span className="text-slate-300 dark:text-slate-600">|</span>
                  <button
                    onClick={handleClearContentTypes}
                    className="text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 font-semibold cursor-pointer"
                  >
                    Clear
                  </button>
                </div>
              </div>

              <div className="space-y-1">
                {CONTENT_TYPES.map((ct) => {
                  const isChecked = filterState.contentTypes.includes(ct.id);
                  return (
                    <label
                      key={ct.id}
                      className={`flex items-start gap-2.5 px-2 py-1.5 rounded cursor-pointer text-xs transition-colors ${
                        isChecked
                          ? 'bg-sky-50/70 dark:bg-sky-950/30'
                          : 'hover:bg-slate-100 dark:hover:bg-[#334155]'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => toggleContentType(ct.id)}
                        className="rounded border-[#cbd5e1] text-[#0284c7] mt-0.5 cursor-pointer"
                      />
                      <span className="truncate leading-tight text-[#0f172a] dark:text-[#f8fafc]">
                        {ct.label}
                      </span>
                    </label>
                  );
                })}
              </div>
            </div>
          )}

          {/* 4. Date & Time Popover */}
          {activeDropdown === 'date' && (
            <div className="w-72">
              <div className="text-[11px] font-bold uppercase text-slate-500 px-2 py-1 border-b border-[#cbd5e1] dark:border-[#334155] mb-2">
                Chronological Scope
              </div>
              <div className="space-y-1">
                {[
                  { id: 'all', label: 'All Dates & Times' },
                  { id: '24h', label: 'Last 24 Hours' },
                  { id: '7d', label: 'Last 7 Days' },
                  { id: '30d', label: 'Last 30 Days' },
                ].map((p) => (
                  <button
                    key={p.id}
                    onClick={() => setDatePreset(p.id)}
                    className={`w-full text-left px-2 py-1.5 rounded text-xs flex items-center justify-between cursor-pointer transition-colors ${
                      filterState.dateRange.preset === p.id
                        ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0369a1] dark:text-[#38bdf8] font-bold'
                        : 'hover:bg-slate-100 dark:hover:bg-[#334155]'
                    }`}
                  >
                    <span>{p.label}</span>
                    {filterState.dateRange.preset === p.id && (
                      <Check className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
                    )}
                  </button>
                ))}
              </div>

              {/* Custom Date Range Section */}
              <div className="mt-3 pt-2 border-t border-[#cbd5e1] dark:border-[#334155]">
                <div className="flex items-center gap-1 text-[11px] font-bold uppercase text-slate-500 mb-2 px-1">
                  <CalendarRange className="w-3 h-3 text-[#0284c7]" />
                  <span>Custom Date Range (UTC)</span>
                </div>
                <div className="space-y-1.5 px-1">
                  <div>
                    <label className="text-[10px] text-slate-400 block mb-0.5">Start Time</label>
                    <input
                      type="datetime-local"
                      value={customStart}
                      onChange={(e) => setCustomStart(e.target.value)}
                      className="w-full bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-[#0284c7]"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] text-slate-400 block mb-0.5">End Time</label>
                    <input
                      type="datetime-local"
                      value={customEnd}
                      onChange={(e) => setCustomEnd(e.target.value)}
                      className="w-full bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-[#0284c7]"
                    />
                  </div>
                  <button
                    onClick={applyCustomDateRange}
                    disabled={!customStart && !customEnd}
                    className="w-full mt-2 py-1 bg-[#0284c7] hover:bg-[#0369a1] disabled:opacity-50 text-white rounded font-semibold text-xs transition-colors cursor-pointer"
                  >
                    Apply Custom Range
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* 5. Keywords Popover */}
          {activeDropdown === 'keywords' && (
            <div className="w-80">
              <div className="flex items-center justify-between px-2 py-1 mb-2 border-b border-[#cbd5e1] dark:border-[#334155]">
                <span className="text-[11px] font-bold uppercase text-slate-500">
                  Filter by Saved Keywords
                </span>
                <button
                  onClick={() => {
                    setActiveDropdown(null);
                    setDropdownPos(null);
                    onOpenKeywordManager();
                  }}
                  className="text-[11px] text-[#0284c7] hover:underline font-bold flex items-center gap-1 cursor-pointer"
                >
                  <span>Manage...</span>
                  <ExternalLink className="w-2.5 h-2.5" />
                </button>
              </div>

              {isLoadingKeywords ? (
                <div className="py-4 text-center text-slate-500 flex items-center justify-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin text-[#0284c7]" />
                  <span>Loading keywords...</span>
                </div>
              ) : caseKeywords.length === 0 ? (
                <div className="py-3 px-2 text-center text-slate-500 text-xs">
                  <p>No keywords added yet.</p>
                  <button
                    onClick={() => {
                      setActiveDropdown(null);
                      setDropdownPos(null);
                      onOpenKeywordManager();
                    }}
                    className="mt-1 text-[#0284c7] font-semibold text-[11.5px] hover:underline cursor-pointer"
                  >
                    + Add or Upload Keywords
                  </button>
                </div>
              ) : (
                <>
                  <div className="flex items-center justify-between px-2 pb-1.5 text-[11px]">
                    <span className="text-slate-400">{caseKeywords.length} keywords</span>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleSelectAllKeywords}
                        className="text-[#0284c7] hover:underline font-semibold cursor-pointer"
                      >
                        Select All
                      </button>
                      <span className="text-slate-300 dark:text-slate-600">|</span>
                      <button
                        onClick={handleClearKeywords}
                        className="text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 font-semibold cursor-pointer"
                      >
                        Clear
                      </button>
                    </div>
                  </div>
                  <div className="max-h-56 overflow-y-auto space-y-1 py-1">
                    {caseKeywords.map((kw) => {
                      const isChecked = filterState.keywords.includes(kw.keyword);
                      return (
                        <label
                          key={kw.keyword_id}
                          className={`flex items-center justify-between px-2 py-1.5 rounded cursor-pointer text-xs transition-colors ${
                            isChecked
                              ? 'bg-sky-50/70 dark:bg-sky-950/30 font-semibold'
                              : 'hover:bg-slate-100 dark:hover:bg-[#334155]'
                          }`}
                        >
                          <div className="flex items-center gap-2 min-w-0 pr-2">
                            <input
                              type="checkbox"
                              checked={isChecked}
                              onChange={() => toggleKeyword(kw.keyword)}
                              className="rounded border-[#cbd5e1] text-[#0284c7] cursor-pointer"
                            />
                            <span className="font-mono truncate">{kw.keyword}</span>
                          </div>
                          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-[#0f172a] text-slate-600 dark:text-slate-400 border border-[#cbd5e1] dark:border-[#334155] shrink-0">
                            {kw.hit_count.toLocaleString()}
                          </span>
                        </label>
                      );
                    })}
                  </div>
                </>
              )}
            </div>
          )}

          {/* 6. Tags & Bookmarks Popover */}
          {activeDropdown === 'tags' && (
            <div className="w-72">
              <div className="flex items-center justify-between px-2 py-1 border-b border-[#cbd5e1] dark:border-[#334155] mb-2">
                <span className="text-[11px] font-bold uppercase text-slate-500">
                  Filter by Forensic Tags
                </span>
                <div className="flex items-center gap-2 text-[11px]">
                  <button
                    onClick={handleSelectAllTags}
                    className="text-[#0284c7] hover:underline font-semibold cursor-pointer"
                  >
                    Select All
                  </button>
                  <span className="text-slate-300 dark:text-slate-600">|</span>
                  <button
                    onClick={handleClearTags}
                    className="text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 font-semibold cursor-pointer"
                  >
                    Clear
                  </button>
                </div>
              </div>
              <div className="space-y-1">
                {TAG_OPTIONS.map((tag) => {
                  const isChecked = filterState.tags.includes(tag.id);
                  return (
                    <label
                      key={tag.id}
                      className={`flex items-center gap-2 px-2 py-1.5 rounded cursor-pointer text-xs transition-colors ${
                        isChecked
                          ? 'bg-sky-50/70 dark:bg-sky-950/30 font-semibold'
                          : 'hover:bg-slate-100 dark:hover:bg-[#334155]'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => toggleTag(tag.id)}
                        className="rounded border-[#cbd5e1] text-[#0284c7] cursor-pointer"
                      />
                      <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${tag.color}`}>
                        {tag.label}
                      </span>
                    </label>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </>
  );
};
