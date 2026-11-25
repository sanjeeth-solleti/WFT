import React, { useState, useMemo } from 'react';
import {
  ChevronDown,
  ChevronRight,
  FileText,
  Search,
  HardDrive,
  Cpu,
  Layers,
  Activity,
  Globe,
  MessageSquare,
  Cloud,
  Mail,
  ShieldAlert,
  Image,
  Usb,
  Sparkles,
  FolderOpen,
  Terminal,
  Database,
  ListTree,
  Lock,
  ExternalLink,
  Compass,
  FileSpreadsheet,
  FileCode,
  Video,
  PhoneCall,
  Users,
  Paperclip,
  Calendar,
  Shield,
} from 'lucide-react';
import { ArtifactItem, ArtifactRegistryResponse } from '../api/client';
import { matchContentType } from './GlobalFilterBar';

interface SidebarTreeProps {
  registryData: ArtifactRegistryResponse | null;
  selectedTable: string | null;
  onSelectArtifact: (artifact: ArtifactItem | null) => void;
  isLoading: boolean;
  contentTypes?: string[];
  onClearContentTypes?: () => void;
  width?: number;
}

// Canonical 9 WFT Examine Categories matching backend/db/schema.py (Event Logs has dedicated dropdown tab)
export const CANONICAL_WFT_CATEGORIES = [
  'REFINED RESULTS',
  'WEB RELATED',
  'CHAT',
  'EMAIL & CALENDAR',
  'CLOUD',
  'MEDIA',
  'DOCUMENTS',
  'OPERATING SYSTEM',
  'MALWARE & YARA',
] as const;

/**
 * Mirrors backend `_build_subview_dedup_predicate` so aggregate row totals
 * (`ALL EVIDENCE`, TopNavBar `Artifacts`, Sidebar footer `Rows`, and per-category badges)
 * never double-count granular SQL slice views when their parent table is present,
 * while keeping granular leaf items visible and clickable inside the tree.
 */
export function buildSubviewDedupPredicate(
  artifactsList: ArtifactItem[]
): (item: ArtifactItem) => boolean {
  const presentTables = new Set<string>();
  const presentIds = new Set<string>();
  for (const a of artifactsList) {
    if ((a.row_count || 0) > 0) {
      if (a.table_name) presentTables.add(a.table_name);
      if (a.artifact_id) presentIds.add(a.artifact_id);
    }
  }
  const hasConcreteMalware =
    presentTables.has('artifact_stinger_hits') ||
    presentTables.has('artifact_yara_hits') ||
    presentTables.has('parsed_suspicious_binaries');
  const hasRawEvtx = presentTables.has('raw_evtx') || presentIds.has('os_evtx');
  const hasViewDocs = presentTables.has('view_documents') || presentIds.has('view_documents');
  const hasRawRecmd =
    presentTables.has('raw_recmd') ||
    presentIds.has('os_recmd') ||
    presentIds.has('registry_recmd');
  const recmdSliceViews = new Set([
    'view_usb_devices',
    'view_autoruns',
    'view_userassist',
    'view_bam_dam',
  ]);

  return (item: ArtifactItem): boolean => {
    const tname = item.table_name || '';
    const aid = item.artifact_id || '';
    if (
      hasConcreteMalware &&
      (tname === 'view_all_malware_detections' || aid === 'malware_all_detections')
    ) {
      return true;
    }
    if (hasRawEvtx && (tname.startsWith('view_evtx_') || aid.startsWith('view_evtx_'))) {
      return true;
    }
    if (tname === 'view_documents' || aid === 'view_documents') {
      return true;
    }
    if (hasRawRecmd && (recmdSliceViews.has(tname) || recmdSliceViews.has(aid))) {
      return true;
    }
    return false;
  };
}

// Normalize arbitrary category string to one of the canonical WFT categories
export function normalizeWftCategory(cat: string): string {
  const c = (cat || '').toUpperCase().trim();
  if (c.includes('REFINED')) return 'REFINED RESULTS';
  if (c.includes('WEB') || c.includes('BROWSER')) return 'WEB RELATED';
  if (c.includes('CHAT') || c.includes('COLLABORATION')) return 'CHAT';
  if (c.includes('EMAIL') || c.includes('CALENDAR') || c.includes('MAIL')) return 'EMAIL & CALENDAR';
  if (c.includes('CLOUD') || c.includes('ONEDRIVE') || c.includes('GDRIVE') || c.includes('DROPBOX')) return 'CLOUD';
  if (c.includes('MEDIA') || c.includes('PICTURE') || c.includes('PHOTO') || c.includes('VIDEO') || c.includes('THUMBCACHE')) return 'MEDIA';
  if (c.includes('DOC') || c.includes('OFFICE') || c.includes('PDF') || c.includes('SPREADSHEET')) return 'DOCUMENTS';
  if (c.includes('EVENT') || c.includes('EVTX')) return 'EVENT LOGS';
  if (c.includes('MALWARE') || c.includes('THREAT') || c.includes('YARA') || c.includes('STINGER')) return 'MALWARE & YARA';
  return 'OPERATING SYSTEM';
}

// Clean Enterprise Forensic Icons
function getCategoryIcon(category: string) {
  switch (category) {
    case 'REFINED RESULTS':
      return <Sparkles className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />;
    case 'WEB RELATED':
      return <Globe className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />;
    case 'CHAT':
      return <MessageSquare className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />;
    case 'EMAIL':
    case 'EMAIL & CALENDAR':
      return <Mail className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />;
    case 'CLOUD':
      return <Cloud className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />;
    case 'MEDIA':
      return <Image className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />;
    case 'DOCUMENTS':
      return <FileText className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />;
    case 'EVENT LOGS':
      return <Activity className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 shrink-0" />;
    case 'OPERATING SYSTEM':
      return <Cpu className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />;
    case 'MALWARE & YARA':
      return <ShieldAlert className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400 shrink-0" />;
    default:
      return <HardDrive className="w-3.5 h-3.5 text-slate-400 shrink-0" />;
  }
}

function getArtifactItemIcon(art: ArtifactItem) {
  const name = (art.display_name + ' ' + art.table_name).toLowerCase();

  // Web Browsers (Chrome, Edge, Brave, Firefox)
  if (name.includes('chrome')) return <Globe className="w-3.5 h-3.5 text-[#4285F4] shrink-0" />;
  if (name.includes('edge')) return <Globe className="w-3.5 h-3.5 text-[#0078D7] shrink-0" />;
  if (name.includes('brave')) return <Globe className="w-3.5 h-3.5 text-[#FB542B] shrink-0" />;
  if (name.includes('firefox')) return <Globe className="w-3.5 h-3.5 text-[#FF7139] shrink-0" />;

  // Chat Applications (Teams, Discord, Slack, Skype, WhatsApp, Telegram, Signal)
  if (name.includes('team') && !name.includes('viewer')) return <MessageSquare className="w-3.5 h-3.5 text-[#6264A7] shrink-0" />;
  if (name.includes('discord')) return <MessageSquare className="w-3.5 h-3.5 text-[#5865F2] shrink-0" />;
  if (name.includes('slack')) return <MessageSquare className="w-3.5 h-3.5 text-[#E01E5A] shrink-0" />;
  if (name.includes('skype')) return <PhoneCall className="w-3.5 h-3.5 text-[#00AFF0] shrink-0" />;
  if (name.includes('whatsapp')) return <MessageSquare className="w-3.5 h-3.5 text-[#25D366] shrink-0" />;
  if (name.includes('telegram')) return <MessageSquare className="w-3.5 h-3.5 text-[#229ED9] shrink-0" />;
  if (name.includes('signal')) return <MessageSquare className="w-3.5 h-3.5 text-[#3A76F0] shrink-0" />;

  // Cloud Providers
  if (name.includes('onedrive')) return <Cloud className="w-3.5 h-3.5 text-[#0078D4] shrink-0" />;
  if (name.includes('gdrive') || name.includes('google drive')) return <Cloud className="w-3.5 h-3.5 text-[#0F9D58] shrink-0" />;
  if (name.includes('dropbox')) return <Cloud className="w-3.5 h-3.5 text-[#0061FF] shrink-0" />;

  // Email
  if (name.includes('outlook') || name.includes('pst') || name.includes('ost')) return <Mail className="w-3.5 h-3.5 text-[#0078D4] shrink-0" />;
  if (name.includes('attachment')) return <Paperclip className="w-3.5 h-3.5 text-amber-500 shrink-0" />;
  if (name.includes('mbox') || name.includes('thunderbird')) return <Mail className="w-3.5 h-3.5 text-[#0A84FF] shrink-0" />;

  // Documents
  if (name.includes('pdf')) return <FileText className="w-3.5 h-3.5 text-[#EA4335] shrink-0" />;
  if (name.includes('word') || name.includes('.doc')) return <FileText className="w-3.5 h-3.5 text-[#2B579A] shrink-0" />;
  if (name.includes('excel') || name.includes('sheet') || name.includes('.xls')) return <FileSpreadsheet className="w-3.5 h-3.5 text-[#217346] shrink-0" />;
  if (name.includes('ppt') || name.includes('powerpoint')) return <FileText className="w-3.5 h-3.5 text-[#D24726] shrink-0" />;
  if (name.includes('txt') || name.includes('plain text') || name.includes('text document') || name.includes('docs_txt')) return <FileText className="w-3.5 h-3.5 text-slate-600 dark:text-slate-300 shrink-0" />;
  if (name.includes('other files') || name.includes('docs_other') || name.includes('code') || name.includes('script') || name.includes('.js') || name.includes('.py') || name.includes('.html') || name.includes('.css')) return <FileCode className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />;

  // Event Logs
  if (name.includes('evtx') || name.includes('event')) return <Activity className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 shrink-0" />;

  // Forensic OS Artifacts
  if (name.includes('prefetch') || name.includes('pecmd')) return <Terminal className="w-3.5 h-3.5 text-indigo-500 shrink-0" />;
  if (name.includes('mft') || name.includes('usn')) return <Database className="w-3.5 h-3.5 text-blue-500 shrink-0" />;
  if (name.includes('lnk') || name.includes('shortcut')) return <ExternalLink className="w-3.5 h-3.5 text-cyan-600 shrink-0" />;
  if (name.includes('jumplist')) return <ListTree className="w-3.5 h-3.5 text-purple-500 shrink-0" />;
  if (name.includes('shimcache') || name.includes('amcache')) return <Cpu className="w-3.5 h-3.5 text-teal-600 shrink-0" />;
  if (name.includes('recmd') || name.includes('registry')) return <Compass className="w-3.5 h-3.5 text-amber-600 shrink-0" />;
  if (name.includes('usb')) return <Usb className="w-3.5 h-3.5 text-emerald-600 shrink-0" />;
  if (name.includes('yara') || name.includes('threat')) return <ShieldAlert className="w-3.5 h-3.5 text-rose-600 shrink-0" />;
  if (name.includes('history') || name.includes('visit')) return <Globe className="w-3.5 h-3.5 text-blue-500 shrink-0" />;
  if (name.includes('download')) return <HardDrive className="w-3.5 h-3.5 text-emerald-600 shrink-0" />;
  if (name.includes('login') || name.includes('password')) return <Lock className="w-3.5 h-3.5 text-amber-500 shrink-0" />;
  if (name.includes('chat') || name.includes('message')) return <MessageSquare className="w-3.5 h-3.5 text-sky-500 shrink-0" />;
  if (name.includes('email') || name.includes('mail')) return <Mail className="w-3.5 h-3.5 text-blue-500 shrink-0" />;
  if (name.includes('cloud')) return <Cloud className="w-3.5 h-3.5 text-sky-500 shrink-0" />;
  if (name.includes('media') || name.includes('image') || name.includes('picture')) return <Image className="w-3.5 h-3.5 text-purple-500 shrink-0" />;
  if (name.includes('video')) return <Video className="w-3.5 h-3.5 text-pink-500 shrink-0" />;
  return <FileText className="w-3.5 h-3.5 text-slate-400 shrink-0" />;
}

export const SidebarTree: React.FC<SidebarTreeProps> = ({
  registryData,
  selectedTable,
  onSelectArtifact,
  isLoading,
  contentTypes = [],
  onClearContentTypes,
  width,
}) => {
  const [searchFilter, setSearchFilter] = useState('');
  const [collapsedCategories, setCollapsedCategories] = useState<Record<string, boolean>>({});

  const toggleCategory = (category: string) => {
    setCollapsedCategories((prev) => ({
      ...prev,
      [category]: !prev[category],
    }));
  };

  // Event Logs and Bulk Extractor have dedicated tabs in the Forensic Views dropdown,
  // so they are excluded from the Artifacts sidebar tree.
  const allPopulated = (registryData?.artifacts || []).filter(
    (a) =>
      a.row_count > 0 &&
      normalizeWftCategory(a.category) !== 'EVENT LOGS' &&
      a.table_name !== 'raw_evtx' &&
      !a.table_name.startsWith('view_evtx_') &&
      a.table_name !== 'view_documents' &&
      a.artifact_id !== 'view_documents' &&
      a.table_name !== 'parsed_documents_metadata' &&
      a.artifact_id !== 'parsed_documents_metadata' &&
      a.table_name !== 'parsed_text_documents' &&
      a.artifact_id !== 'parsed_text_documents' &&
      a.table_name !== 'parsed_bulk_extractor_features' &&
      a.table_name !== 'parsed_bulk_extractor_histograms' &&
      a.artifact_id !== 'bulk_extractor_features' &&
      a.artifact_id !== 'bulk_extractor_histograms'
  );
  const hasConcreteMalwareTable = allPopulated.some(
    (a) =>
      a.table_name === 'artifact_stinger_hits' ||
      a.table_name === 'artifact_yara_hits' ||
      a.table_name === 'parsed_suspicious_binaries'
  );
  const rawArtifacts = allPopulated.filter(
    (a) => !(hasConcreteMalwareTable && a.table_name === 'view_all_malware_detections')
  );
  const contentTypeFiltered =
    contentTypes.length > 0
      ? rawArtifacts.filter((a) => matchContentType(a, contentTypes))
      : rawArtifacts;
  const artifacts = contentTypeFiltered.filter((a) => a.row_count > 0);
  const isDuplicateSubview = useMemo(
    () => buildSubviewDedupPredicate(allPopulated),
    [allPopulated]
  );
  const computedDedupTotal = artifacts.reduce(
    (acc, a) => acc + (isDuplicateSubview(a) ? 0 : a.row_count),
    0
  );
  const fullRegistryPopulated = (registryData?.artifacts || []).filter((a) => a.row_count > 0);
  const isDuplicateFull = useMemo(
    () => buildSubviewDedupPredicate(fullRegistryPopulated),
    [fullRegistryPopulated]
  );
  const computedFullDedupTotal = fullRegistryPopulated.reduce(
    (acc, a) => acc + (isDuplicateFull(a) ? 0 : a.row_count),
    0
  );
  const totalAllRows =
    contentTypes.length === 0 &&
    typeof registryData?.all_evidence_total === 'number' &&
    registryData.all_evidence_total > 0
      ? registryData.all_evidence_total
      : contentTypes.length === 0
      ? computedFullDedupTotal
      : computedDedupTotal || artifacts.reduce((acc, a) => acc + a.row_count, 0);

  // Group into Canonical 10 Categories
  // Strictly hide any artifact sub-item with row_count === 0, and hide any parent category whose children sum to 0
  const groupedCategories = useMemo(() => {
    const groups: Record<string, ArtifactItem[]> = {};
    CANONICAL_WFT_CATEGORIES.forEach((c) => {
      groups[c] = [];
    });

    artifacts.forEach((art) => {
      if (art.row_count <= 0) return;
      const canonicalCat = normalizeWftCategory(art.category);
      if (!groups[canonicalCat]) {
        groups[canonicalCat] = [];
      }
      groups[canonicalCat].push(art);
    });

    const filtered: Record<string, ArtifactItem[]> = {};
    Object.entries(groups).forEach(([category, items]) => {
      const activeItems = items.filter((item) => item.row_count > 0);
      const matched = activeItems.filter((item) => {
        if (!searchFilter.trim()) return true;
        const q = searchFilter.toLowerCase();
        return (
          item.display_name.toLowerCase().includes(q) ||
          item.table_name.toLowerCase().includes(q) ||
          category.toLowerCase().includes(q)
        );
      });
      const dedupSum = matched.reduce(
        (sum, item) => sum + (isDuplicateSubview(item) ? 0 : item.row_count),
        0
      );
      const categorySum =
        dedupSum > 0 ? dedupSum : matched.reduce((sum, item) => sum + item.row_count, 0);
      // Strictly omit any parent category whose visible children sum to 0
      if (matched.length > 0 && categorySum > 0) {
        filtered[category] = matched;
      }
    });

    return filtered;
  }, [artifacts, searchFilter, isDuplicateSubview]);

  // Categories with visible, positive-count artifacts
  const visibleCategories = useMemo(() => {
    return CANONICAL_WFT_CATEGORIES.filter((category) => {
      const items = groupedCategories[category] || [];
      return items.length > 0 && items.reduce((sum, item) => sum + item.row_count, 0) > 0;
    });
  }, [groupedCategories]);

  const isAllEvidenceSelected = selectedTable === null;

  return (
    <aside
      style={{ width: width !== undefined ? `${width}px` : undefined }}
      className={`${
        width !== undefined ? '' : 'w-80'
      } bg-white dark:bg-[#1e293b] border-r border-[#cbd5e1] dark:border-[#334155] flex flex-col h-full select-none shadow-xs shrink-0 overflow-hidden font-sans`}
    >
      {/* Header & Search */}
      <div className="p-3 border-b border-[#cbd5e1] dark:border-[#334155] flex flex-col gap-2 shrink-0 bg-[#f1f5f9] dark:bg-[#0f172a]">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#0f172a] dark:text-[#f8fafc]">
            <Layers className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
            <span>Artifact Categories</span>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white dark:bg-[#1e293b] text-slate-600 dark:text-slate-300 font-semibold border border-[#cbd5e1] dark:border-[#334155]">
            {visibleCategories.length} Categories
          </span>
        </div>

        {/* Content Type Filter Banner */}
        {contentTypes.length > 0 && (
          <div className="flex items-center justify-between px-2 py-1 bg-sky-50 dark:bg-sky-950/40 border border-sky-200 dark:border-sky-800 rounded text-[11px] text-sky-800 dark:text-sky-300">
            <span>Filtered by {contentTypes.length} content type(s)</span>
            {onClearContentTypes && (
              <button
                onClick={onClearContentTypes}
                className="font-bold hover:underline cursor-pointer text-[#0284c7] dark:text-[#38bdf8]"
              >
                Clear
              </button>
            )}
          </div>
        )}

        {/* Quick Search Box */}
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400 pointer-events-none" />
          <input
            type="text"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder="Search artifact types..."
            className="w-full bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] hover:border-slate-400 focus:border-[#0284c7] text-[#0f172a] dark:text-[#f8fafc] placeholder-slate-400 text-xs rounded pl-9 pr-7 py-1.5 focus:outline-none focus:ring-1 focus:ring-[#0284c7] font-sans transition-colors"
          />
          {searchFilter && (
            <button
              onClick={() => setSearchFilter('')}
              className="absolute right-2.5 top-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 text-xs cursor-pointer"
              title="Clear"
            >
              ✕
            </button>
          )}
        </div>

        {/* Active Types Filter Badge */}
        <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400 px-0.5">
          <span className="font-semibold text-[11px] text-[#0284c7] dark:text-[#38bdf8]">
            Active Artifacts Only
          </span>
          <span className="font-mono text-[10.5px]">
            {artifacts.length} active types
          </span>
        </div>
      </div>

      {/* Spacious Hierarchical Tree */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden p-2 space-y-1.5 text-xs bg-slate-50/50 dark:bg-[#0f172a]/50">
        {/* Top Item: ALL EVIDENCE showing total case count in bold on right */}
        {!searchFilter && (
          <button
            onClick={() => onSelectArtifact(null)}
            className={`w-full px-3 py-2.5 rounded flex items-center justify-between text-left transition-all border cursor-pointer ${
              isAllEvidenceSelected
                ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] border-[#0284c7] dark:border-[#38bdf8] text-[#0f172a] dark:text-[#f8fafc] font-bold shadow-2xs'
                : 'bg-white dark:bg-[#1e293b] hover:bg-slate-100 dark:hover:bg-[#334155] border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc]'
            }`}
            title="All Evidence Items in Active Case"
          >
            <div className="flex items-center gap-2.5 min-w-0">
              <FolderOpen className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />
              <span className="font-bold text-xs uppercase tracking-wide truncate">
                ALL EVIDENCE
              </span>
            </div>
            <span className="font-mono font-bold text-xs text-[#0284c7] dark:text-[#38bdf8] shrink-0 ml-2">
              {totalAllRows.toLocaleString()}
            </span>
          </button>
        )}

        {/* Loading Spinner */}
        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-12 text-slate-400 gap-2">
            <div className="w-5 h-5 border-2 border-[#0284c7] border-t-transparent rounded-full animate-spin" />
            <span className="text-xs font-mono">Loading Artifact Registry...</span>
          </div>
        ) : visibleCategories.length === 0 ? (
          <div className="py-12 px-4 text-center text-slate-400 text-xs font-sans">
            No active evidence records in case.
          </div>
        ) : (
          visibleCategories.map((category) => {
            const items = (groupedCategories[category] || []).filter((item) => item.row_count > 0);
            if (items.length === 0) return null;

            const dedupCatRows = items.reduce(
              (sum, item) => sum + (isDuplicateSubview(item) ? 0 : item.row_count),
              0
            );
            const categoryRowCount =
              dedupCatRows > 0
                ? dedupCatRows
                : items.reduce((sum, item) => sum + item.row_count, 0);
            if (categoryRowCount <= 0) return null;
            const isCollapsed = Boolean(collapsedCategories[category]);

            return (
              <div
                key={category}
                className="rounded border border-[#cbd5e1] dark:border-[#334155] overflow-hidden bg-white dark:bg-[#1e293b] shadow-2xs"
              >
                {/* Parent Category Header (Uppercase Bold) */}
                <button
                  onClick={() => toggleCategory(category)}
                  className="w-full px-3 py-2 flex items-center justify-between text-left bg-[#f8fafc] dark:bg-[#1e293b] hover:bg-slate-100 dark:hover:bg-[#334155] transition-colors group border-b border-[#cbd5e1] dark:border-[#334155] cursor-pointer"
                >
                  <div className="flex items-center gap-2 min-w-0 overflow-hidden pr-2">
                    <span className="text-slate-400 group-hover:text-slate-600 dark:group-hover:text-slate-200 shrink-0">
                      {isCollapsed ? (
                        <ChevronRight className="w-3.5 h-3.5" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5" />
                      )}
                    </span>
                    {getCategoryIcon(category)}
                    <span className="font-bold text-xs tracking-wide text-[#0f172a] dark:text-[#f8fafc] truncate uppercase">
                      {category}
                    </span>
                  </div>

                  <span className="font-mono font-bold text-[11px] text-slate-600 dark:text-slate-400 shrink-0 ml-1">
                    {categoryRowCount.toLocaleString()}
                  </span>
                </button>

                {/* Child Artifacts - strictly row_count > 0 */}
                {!isCollapsed && (
                  <div className="bg-white dark:bg-[#1e293b] divide-y divide-[#e2e8f0] dark:divide-[#334155]">
                    {items.map((art) => {
                        const isSelected = selectedTable === art.table_name;
                        return (
                          <button
                            key={art.artifact_id}
                            onClick={() => onSelectArtifact(art)}
                            className={`w-full py-1.5 px-3 flex items-center justify-between text-left transition-colors cursor-pointer ${
                              isSelected
                                ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0f172a] dark:text-[#f8fafc] font-bold border-l-4 border-l-[#0284c7] dark:border-l-[#38bdf8]'
                                : 'text-[#0f172a] dark:text-[#cbd5e1] hover:bg-slate-100 dark:hover:bg-[#334155]'
                            }`}
                            title={`${art.display_name} (${art.table_name})`}
                          >
                            <div className="flex items-center gap-2 min-w-0 pr-2">
                              {getArtifactItemIcon(art)}
                              <span className="truncate text-[12px] leading-snug">
                                {art.display_name}
                              </span>
                            </div>

                            <span
                              className={`font-mono text-[11px] shrink-0 ml-1 ${
                                isSelected
                                  ? 'text-[#0284c7] dark:text-[#38bdf8] font-bold'
                                  : 'text-slate-500 dark:text-slate-400 font-medium'
                              }`}
                            >
                              {art.row_count.toLocaleString()}
                            </span>
                          </button>
                        );
                      })}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Left Sidebar Footer */}
      <div className="p-2.5 border-t border-[#cbd5e1] dark:border-[#334155] bg-[#f1f5f9] dark:bg-[#0f172a] text-xs font-mono text-slate-600 dark:text-slate-400 flex items-center justify-between shrink-0">
        <span>Artifact Tables: {artifacts.length}</span>
        <span className="text-[#0284c7] dark:text-[#38bdf8] font-bold">
          {totalAllRows.toLocaleString()} Rows
        </span>
      </div>
    </aside>
  );
};