import React, { useState, useEffect, useRef } from 'react';
import {
  Play,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Terminal,
  Cpu,
  Shield,
  RefreshCw,
  FolderOpen,
  Zap,
  Activity,
  Search,
  FileText,
  Disc,
  ListChecks,
  ArrowLeft,
  ArrowRight,
  Eye,
  Check,
  X,
  Hash,
} from 'lucide-react';
import {
  apiClient,
  ProcessCaseRequest,
  CaseStatusResponse,
  ProcessingLog,
  ValidatePathResponse,
} from '../api/client';
import { KeywordManager, StagedKeywordItem } from './KeywordManagerModal';
import { FileBrowserModal } from './FileBrowserModal';
import { useResizable, ResizeHandle } from './ResizeHandle';

interface ProcessWizardProps {
  currentCaseId: string;
  onCaseCreated: (newCaseId: string) => void;
  isOpenAsModal?: boolean;
  onCloseModal?: () => void;
  onNavigateToExamine?: () => void;
}

interface CatalogItem {
  id: string;
  name: string;
  tool: string;
  desc: string;
}

interface CategoryCatalog {
  category: string;
  icon: string;
  items: CatalogItem[];
}

const ARTIFACT_CATEGORIES_CATALOG: CategoryCatalog[] = [
  {
    category: 'Operating System',
    icon: 'os',
    items: [
      { id: 'os_evtx', name: 'Event Logs (EVTX)', tool: 'EvtxECmd.exe', desc: 'Security, System, PowerShell, Sysmon, Defender, TerminalServices' },
      { id: 'os_tasks', name: 'Scheduled Tasks (XML)', tool: 'CorporateIRParser', desc: 'Windows scheduled job definitions, triggers, and execution actions' },
      { id: 'os_powershell', name: 'PowerShell History', tool: 'CorporateIRParser', desc: 'ConsoleHost_history.txt command-line audit trail' },
      { id: 'os_wpn_notifications', name: 'Push Notifications', tool: 'CorporateIRParser', desc: 'Windows push notifications database (wpndatabase.db)' },
      { id: 'os_wxt_activity', name: 'Windows Timeline Activities', tool: 'WxTCmd.exe', desc: 'User activity history and app engagement from ActivitiesCache.db' },
    ],
  },
  {
    category: 'Program Execution',
    icon: 'exec',
    items: [
      { id: 'os_prefetch', name: 'Prefetch (PECmd)', tool: 'PECmd.exe', desc: 'Process executions, run counts, volume serials, loaded DLLs' },
      { id: 'os_amcache_files', name: 'Amcache File Entries', tool: 'AmcacheParser.exe', desc: 'Unassociated files, installed programs, and SHA1 hashes' },
      { id: 'os_shimcache', name: 'AppCompatCache (ShimCache)', tool: 'AppCompatCacheParser.exe', desc: 'Application compatibility database and executed binary paths' },
      { id: 'view_userassist', name: 'UserAssist Execution', tool: 'RECmd.exe', desc: 'GUI program launches decrypted from ROT13 UserAssist keys' },
      { id: 'view_bam_dam', name: 'BAM / DAM Execution', tool: 'RECmd.exe', desc: 'Background Activity Moderator & Desktop Activity Moderator execution' },
      { id: 'os_recentfilecache', name: 'RecentFileCache', tool: 'RecentFileCacheParser.exe', desc: 'RecentFileCache.bcf execution paths for Windows 7/8/Server' },
    ],
  },
  {
    category: 'File System',
    icon: 'fs',
    items: [
      { id: 'fs_mft', name: 'Master File Table ($MFT)', tool: 'MFTECmd.exe', desc: 'NTFS master file table: $STANDARD_INFORMATION & $FILE_NAME timestamps' },
      { id: 'fs_usnjrnl', name: 'USN Change Journal ($J)', tool: 'MFTECmd.exe', desc: 'NTFS change journal tracking file modifications, deletions, and moves' },
      { id: 'fs_shellbags', name: 'ShellBags (Folder Access)', tool: 'SBECmd.exe', desc: 'Folder access history, desktop view preferences, and network shares' },
      { id: 'fs_lnk', name: 'LNK Shortcut Files', tool: 'LECmd.exe', desc: 'Windows shortcut files tracking opened documents, drives, and MAC addresses' },
      { id: 'fs_jumplist_auto', name: 'Jump Lists (Auto & Custom)', tool: 'JLECmd.exe', desc: 'AutomaticDestinations and CustomDestinations taskbar jump lists' },
      { id: 'fs_recyclebin', name: 'Recycle Bin ($I)', tool: 'RBCmd.exe', desc: 'Deleted file records, original paths, file sizes, deletion timestamps' },
    ],
  },
  {
    category: 'Recovery, Carving & Bulk Extractor',
    icon: 'recovery',
    items: [
      {
        id: 'fs_vss',
        name: 'Volume Shadow Copies (VSS)',
        tool: 'pyvshadow / dissect.vss',
        desc: 'Enumerate offline & live NTFS Volume Shadow Copy snapshots and differentially parse historical/deleted Registry, EVTX, Browser, and user files',
      },
      {
        id: 'carve_files',
        name: 'Data Carving (Unallocated & Deleted)',
        tool: 'DataCarver (Multi-Threaded)',
        desc: 'Multi-threaded signature & structural carving of deleted JPEG, PNG, GIF, PDF, Office/ZIP, SQLite, EVTX, Registry, LNK, PST/OST, and PE files',
      },
      {
        id: 'bulk_extractor',
        name: 'Bulk Extractor (Open-Source Feature & IOC Scanner)',
        tool: 'bulk_extractor64.exe (-j threads)',
        desc: 'High-speed C++ multi-threaded stream & E01 scanner extracting emails, URLs, domains, IPs, EXIF, WinPE, LNK, Prefetch, and carved streams',
      },
    ],
  },
  {
    category: 'Registry & OS',
    icon: 'reg',
    items: [
      { id: 'registry_recmd', name: 'Registry Hives (RECmd)', tool: 'RECmd.exe', desc: 'Kroll Batch RECmd registry hive analysis across SYSTEM, SOFTWARE, NTUSER' },
      { id: 'view_autoruns', name: 'AutoRuns & Persistence', tool: 'RECmd.exe', desc: 'Run keys, Services, Winlogon, Image File Execution Options' },
      { id: 'sqlecmd', name: 'SQLECmd SQLite Hunting', tool: 'SQLECmd.exe', desc: 'Map-driven SQLite forensic hunting across Windows & application databases' },
    ],
  },
  {
    category: 'Network & SRUM',
    icon: 'net',
    items: [
      { id: 'network_srum_app', name: 'SRUM App Resource Usage', tool: 'SrumECmd.exe', desc: 'System Resource Usage Monitor: CPU runtime, foreground/background cycles' },
      { id: 'network_srum_net', name: 'SRUM Network Data Usage', tool: 'SrumECmd.exe', desc: 'Bytes sent and received per executable and network interface' },
      { id: 'network_srum_conn', name: 'SRUM Network Connections', tool: 'SrumECmd.exe', desc: 'Connected duration, timestamps, and interface LUIDs' },
      { id: 'network_sum', name: 'User Access Logging (SUM)', tool: 'SumECmd.exe', desc: 'Server user access logging database (Current.mdb)' },
    ],
  },
  {
    category: 'USB & External Devices',
    icon: 'usb',
    items: [
      { id: 'usb_devices', name: 'Connected USB Devices', tool: 'USBDeviceCorrelator', desc: 'Correlated USB devices: vendor, product, serial number, volume GUIDs' },
      { id: 'view_usb_devices', name: 'USB Registry Activity', tool: 'RECmd.exe', desc: 'USBSTOR, MountedDevices, and EMDMgmt registry keys' },
    ],
  },
  {
    category: 'Web Related',
    icon: 'web',
    items: [
      { id: 'browser_history', name: 'Browser History', tool: 'ChromiumParser / FirefoxParser', desc: 'Chrome, Edge, Brave, and Firefox visited URLs and visit timestamps' },
      { id: 'browser_downloads', name: 'Browser Downloads', tool: 'ChromiumParser', desc: 'Downloaded filenames, source URLs, danger types, and file sizes' },
      { id: 'browser_logins', name: 'Saved Logins & Passwords', tool: 'ChromiumParser', desc: 'Origin URLs, usernames, created dates, and usage counts' },
    ],
  },
  {
    category: 'Chat & Collaboration',
    icon: 'chat',
    items: [
      { id: 'chat_messages', name: 'Chat Messages', tool: 'ChatParser', desc: 'Microsoft Teams, Discord, and Slack message records and timestamps' },
      { id: 'parsed_notifications', name: 'App Toast Notifications', tool: 'ChatParser', desc: 'Windows Push Notification database toast alerts' },
      { id: 'parsed_rmm_sessions', name: 'Remote Desktop & RMM Sessions', tool: 'CorporateIRParser', desc: 'AnyDesk, TeamViewer, and RustDesk incoming/outgoing connection logs' },
    ],
  },
  {
    category: 'Email & Calendar',
    icon: 'email',
    items: [
      { id: 'emails', name: 'Emails & Mailboxes', tool: 'EmailParser', desc: 'Outlook PST, OST, MSG, and RFC 822 EML messages with attachment extraction' },
    ],
  },
  {
    category: 'Cloud',
    icon: 'cloud',
    items: [
      { id: 'cloud_files', name: 'Cloud Storage Synced Files', tool: 'CloudParser', desc: 'OneDrive SyncEngineDatabase and Google Drive metadata' },
    ],
  },
  {
    category: 'Documents',
    icon: 'doc',
    items: [
      { id: 'documents_metadata', name: 'Documents & Zone.Identifier', tool: 'DocumentParser', desc: 'Office & PDF metadata, authors, and Mark-of-the-Web (MOTW) Zone.Identifier' },
    ],
  },
  {
    category: 'Media',
    icon: 'media',
    items: [
      { id: 'media_files', name: 'Carved Media & EXIF Metadata', tool: 'MediaParser', desc: 'JPEG, PNG, MP4, thumbcache extraction and EXIF camera geolocation' },
    ],
  },
  {
    category: 'Malware & Threat Hunting',
    icon: 'shield',
    items: [
      { id: 'file_enrichment', name: 'SHA256 & Threat Analysis', tool: 'FileEnrichmentEngine', desc: 'Cryptographic hashing, extension mismatch, and archive unpacking' },
      { id: 'artifact_yara_hits', name: 'YARA-X Malware Rule Matches', tool: 'YARA-X', desc: 'Compiled rule scanning for webshells, beacons, mimikatz, credential dumpers' },
      { id: 'artifact_stinger_hits', name: 'Trellix Stinger Malware Scan', tool: 'stinger64.exe', desc: 'Trellix Stinger rootkit, trojan, and malware binary signature scanning' },
      { id: 'artifact_ocr_results', name: 'RapidOCR Text Extraction', tool: 'RapidOCR', desc: 'OnnxRuntime optical character recognition for screenshots, memes, and scans' },
    ],
  },
];

const HEAVY_OPT_IN_IDS = new Set(['fs_vss', 'carve_files', 'bulk_extractor']);
const ALL_CATALOG_IDS = new Set<string>(
  ARTIFACT_CATEGORIES_CATALOG.flatMap((cat) => cat.items.map((item) => item.id))
);

function normPath(p: string): string {
  return (p || '').trim().replace(/^["']|["']$/g, '').replace(/[\\/]+$/, '').toLowerCase();
}

function isSameOrSubpath(targetRaw: string, sourceRaw: string): boolean {
  const normTarget = normPath(targetRaw);
  const normSource = normPath(sourceRaw);
  if (!normTarget || !normSource) return false;
  return (
    normTarget === normSource ||
    normTarget.startsWith(normSource + '\\') ||
    normTarget.startsWith(normSource + '/')
  );
}

export const ProcessWizard: React.FC<ProcessWizardProps> = ({
  currentCaseId,
  onCaseCreated,
  isOpenAsModal = false,
  onCloseModal,
  onNavigateToExamine,
}) => {
  const [currentStep, setCurrentStep] = useState<number>(1);

  const [caseName, setCaseName] = useState(`Incident_${new Date().toISOString().slice(0, 10).replace(/-/g, '')}`);
  const [caseNumber, setCaseNumber] = useState(`DFIR-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`);
  const [examinerName, setExaminerName] = useState('');
  const [caseNotes, setCaseNotes] = useState('');

  const [sourceType, setSourceType] = useState<'folder' | 'live_triage' | 'image' | 'directory'>('image');
  const [sourcePath, setSourcePath] = useState('');

  const [pathValidation, setPathValidation] = useState<ValidatePathResponse | null>(null);
  const [isValidatingPath, setIsValidatingPath] = useState<boolean>(false);
  const [targetStorageDir, setTargetStorageDir] = useState<string>('');

  const [fileBrowserOpen, setFileBrowserOpen] = useState<boolean>(false);
  const [fileBrowserMode, setFileBrowserMode] = useState<'file' | 'folder'>('file');
  const [fileBrowserTarget, setFileBrowserTarget] = useState<'evidence' | 'storage'>('evidence');

  const openInAppBrowser = (target: 'evidence' | 'storage', mode: 'file' | 'folder') => {
    setFileBrowserTarget(target);
    setFileBrowserMode(mode);
    setFileBrowserOpen(true);
  };

  const handleInAppSelect = (selectedPath: string) => {
    const clean = selectedPath.trim().replace(/^["']|["']$/g, '').trim();
    if (fileBrowserTarget === 'evidence') {
      setSourcePath(clean);
      const lower = clean.toLowerCase();
      const isImg = ['.e01', '.ex01', '.vhdx', '.vhd', '.vmdk', '.raw', '.dd', '.img', '.iso', '.001'].some(ext => lower.endsWith(ext));
      setSourceType(isImg ? 'image' : 'folder');
      validateInputPath(clean);
    } else {
      setTargetStorageDir(clean);
    }
  };

  const validateInputPath = async (p: string) => {
    const clean = p.trim().replace(/^["']|["']$/g, '').trim();
    if (!clean) {
      setPathValidation(null);
      return;
    }
    setIsValidatingPath(true);
    try {
      const res = await apiClient.validatePath(clean);
      setPathValidation(res);
      if (res.valid) {
        if (res.is_dir) {
          setSourceType('folder');
        } else if (res.is_image || res.is_file) {
          setSourceType('image');
        }
      }
    } catch (err) {
      setPathValidation({
        valid: false,
        exists: false,
        path: clean,
        error: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setIsValidatingPath(false);
    }
  };

  useEffect(() => {
    if (!sourcePath.trim()) {
      setPathValidation(null);
      return;
    }
    const clean = sourcePath.trim().replace(/^["']|["']$/g, '').trim();
    const timer = setTimeout(() => {
      validateInputPath(clean);
    }, 350);
    return () => clearTimeout(timer);
  }, [sourcePath]);

  const [selectedPreset, setSelectedPreset] = useState<'quick' | 'comprehensive' | 'malware' | 'custom'>('custom');
  const [selectedCategory, setSelectedCategory] = useState<string>('Operating System');
  const [selectedArtifactIds, setSelectedArtifactIds] = useState<Set<string>>(() => {
    const std = new Set<string>();
    ARTIFACT_CATEGORIES_CATALOG.forEach((cat) =>
      cat.items.forEach((item) => {
        if (!HEAVY_OPT_IN_IDS.has(item.id)) {
          std.add(item.id);
        }
      })
    );
    std.add('web_hindsight');
    return std;
  });
  const [enableYara, setEnableYara] = useState(true);
  const [enableIoc, setEnableIoc] = useState(true);
  const [enableOcr, setEnableOcr] = useState(true);
  const [enableStinger, setEnableStinger] = useState(true);
  const [enableHindsight, setEnableHindsight] = useState(true);
  const [maxWorkers, setMaxWorkers] = useState<number>(25);
  const [initialKeywords, setInitialKeywords] = useState<StagedKeywordItem[]>([]);
  const [step3SubTab, setStep3SubTab] = useState<'artifacts' | 'keywords'>('artifacts');

  // Strictly synchronized booleans & catalog count from Step 3 checkboxes:
  const enableVss = selectedArtifactIds.has('fs_vss');
  const enableDataCarving = selectedArtifactIds.has('carve_files');
  const enableBulkExtractor = selectedArtifactIds.has('bulk_extractor');
  const selectedCatalogCount = Array.from(selectedArtifactIds).filter((id) =>
    ALL_CATALOG_IDS.has(id)
  ).length;

  const isTargetSameAsSource = isSameOrSubpath(targetStorageDir, sourcePath);

  const step3ContainerRef = useRef<HTMLDivElement>(null);
  const step3Left = useResizable({
    initialWidth: 288,
    minWidth: 200,
    maxWidth: 500,
    storageKey: 'wft_process_step3_left_width',
    direction: 'left',
    containerRef: step3ContainerRef,
    minCenterWidth: 320,
  });

  const [activeCaseId, setActiveCaseId] = useState<string>(currentCaseId);
  const [statusData, setStatusData] = useState<CaseStatusResponse | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submissionError, setSubmissionError] = useState<string | null>(null);
  const [logSearch, setLogSearch] = useState('');
  const [moduleFilter, setModuleFilter] = useState('ALL');
  const [isLogDrawerExpanded, setIsLogDrawerExpanded] = useState(false);

  useEffect(() => {
    if (currentCaseId) {
      setActiveCaseId(currentCaseId);
    }
  }, [currentCaseId]);

  useEffect(() => {
    if (!activeCaseId) return;
    setStatusData((prev) => (prev && prev.case_id !== activeCaseId ? null : prev));

    let isMounted = true;
    const fetchStatus = async () => {
      try {
        const res = await apiClient.getCaseStatus(activeCaseId);
        if (isMounted) {
          setStatusData(res);
        }
      } catch (err) {
        console.warn(`Failed to fetch status for case ${activeCaseId}:`, err);
      }
    };

    fetchStatus();

    const interval = setInterval(() => {
      if (statusData?.status === 'RUNNING' || isSubmitting) {
        fetchStatus();
      }
    }, 2000);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [activeCaseId, statusData?.status, isSubmitting]);

  const syncEngineBooleansFromSet = (ids: Set<string>, includeHindsight = false) => {
    setEnableYara(ids.has('artifact_yara_hits'));
    setEnableStinger(ids.has('artifact_stinger_hits'));
    setEnableOcr(ids.has('artifact_ocr_results'));
    setEnableIoc(ids.has('file_enrichment'));
    if (includeHindsight) {
      setEnableHindsight(ids.has('web_hindsight'));
    }
  };

  const handleEngineSwitchChange = (
    engine: 'yara' | 'stinger' | 'ocr' | 'ioc' | 'hindsight',
    checked: boolean
  ) => {
    setSelectedPreset('custom');
    const idMap: Record<'yara' | 'stinger' | 'ocr' | 'ioc' | 'hindsight', string> = {
      yara: 'artifact_yara_hits',
      stinger: 'artifact_stinger_hits',
      ocr: 'artifact_ocr_results',
      ioc: 'file_enrichment',
      hindsight: 'web_hindsight',
    };
    const targetId = idMap[engine];
    if (engine === 'yara') setEnableYara(checked);
    else if (engine === 'stinger') setEnableStinger(checked);
    else if (engine === 'ocr') setEnableOcr(checked);
    else if (engine === 'ioc') setEnableIoc(checked);
    else if (engine === 'hindsight') setEnableHindsight(checked);

    setSelectedArtifactIds((prev) => {
      const next = new Set(prev);
      if (checked) next.add(targetId);
      else next.delete(targetId);
      return next;
    });
  };

  const applyPreset = (preset: 'quick' | 'comprehensive' | 'malware') => {
    const next = new Set<string>();
    if (preset === 'quick') {
      [
        'os_evtx',
        'os_prefetch',
        'fs_lnk',
        'os_shimcache',
        'usb_devices',
        'browser_history',
        'registry_recmd',
        'view_autoruns',
      ].forEach((id) => next.add(id));
      setSelectedArtifactIds(next);
      setEnableYara(false);
      setEnableIoc(false);
      setEnableOcr(false);
      setEnableStinger(false);
      setEnableHindsight(false);
      setSelectedPreset('quick');
    } else if (preset === 'malware') {
      ARTIFACT_CATEGORIES_CATALOG.forEach((cat) =>
        cat.items.forEach((item) => {
          if (
            item.id !== 'fs_vss' &&
            item.id !== 'carve_files' &&
            item.id !== 'artifact_ocr_results'
          ) {
            next.add(item.id);
          }
        })
      );
      next.add('bulk_extractor');
      next.add('web_hindsight');
      setSelectedArtifactIds(next);
      setEnableYara(true);
      setEnableIoc(true);
      setEnableStinger(true);
      setEnableHindsight(true);
      setEnableOcr(false);
      setSelectedPreset('malware');
    } else {
      // Comprehensive IR: checks ALL 43 catalog items including fs_vss, carve_files, bulk_extractor + web_hindsight
      ARTIFACT_CATEGORIES_CATALOG.forEach((cat) => cat.items.forEach((item) => next.add(item.id)));
      next.add('web_hindsight');
      setSelectedArtifactIds(next);
      setEnableYara(true);
      setEnableIoc(true);
      setEnableOcr(true);
      setEnableStinger(true);
      setEnableHindsight(true);
      setSelectedPreset('comprehensive');
    }
  };

  const toggleArtifact = (id: string) => {
    setSelectedPreset('custom');
    setSelectedArtifactIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      syncEngineBooleansFromSet(next, false);
      return next;
    });
  };

  const toggleCategoryAll = (catName: string, select: boolean) => {
    const cat = ARTIFACT_CATEGORIES_CATALOG.find((c) => c.category === catName);
    if (!cat) return;
    setSelectedPreset('custom');
    setSelectedArtifactIds((prev) => {
      const next = new Set(prev);
      cat.items.forEach((item) => {
        if (select) next.add(item.id);
        else next.delete(item.id);
      });
      syncEngineBooleansFromSet(next, false);
      return next;
    });
  };

  const toggleAllGlobally = (select: boolean) => {
    setSelectedPreset('custom');
    const next = new Set<string>();
    if (select) {
      ARTIFACT_CATEGORIES_CATALOG.forEach((cat) => cat.items.forEach((item) => next.add(item.id)));
      next.add('web_hindsight');
    }
    setSelectedArtifactIds(next);
    syncEngineBooleansFromSet(next, true);
  };

  // Single-click Process Evidence: starts immediately and jumps directly to live execution monitor
  const handleStartProcessing = async () => {
    if (isSubmitting || statusData?.status === 'RUNNING') return;
    setIsSubmitting(true);
    setSubmissionError(null);

    const finalSourcePath = sourcePath.trim().replace(/^["']|["']$/g, '').trim();
    if (!finalSourcePath) {
      setSubmissionError('Please select an evidence folder or forensic disk image in Step 2 first.');
      setCurrentStep(2);
      setIsSubmitting(false);
      return;
    }

    const cleanTarget = targetStorageDir.trim().replace(/^["']|["']$/g, '').trim();
    if (cleanTarget && isSameOrSubpath(cleanTarget, finalSourcePath)) {
      setSubmissionError(
        'Target Case / Output Folder must not be the same as the Evidence Source path (or a subfolder inside it).'
      );
      setIsSubmitting(false);
      return;
    }

    try {
      const clampedWorkers = Math.max(1, Math.min(32, Number(maxWorkers) || 25));
      const outgoingSet = new Set(selectedArtifactIds);
      if (enableYara) outgoingSet.add('artifact_yara_hits');
      else outgoingSet.delete('artifact_yara_hits');
      if (enableStinger) outgoingSet.add('artifact_stinger_hits');
      else outgoingSet.delete('artifact_stinger_hits');
      if (enableOcr) outgoingSet.add('artifact_ocr_results');
      else outgoingSet.delete('artifact_ocr_results');
      if (enableIoc) outgoingSet.add('file_enrichment');
      else outgoingSet.delete('file_enrichment');
      if (enableHindsight) outgoingSet.add('web_hindsight');
      else outgoingSet.delete('web_hindsight');
      const selectedList = Array.from(outgoingSet);

      const req: ProcessCaseRequest = {
        case_name: caseName.trim(),
        source_type: sourceType,
        source_path: finalSourcePath,
        target_dir: cleanTarget || undefined,
        case_number: caseNumber.trim(),
        examiner: examinerName.trim(),
        notes: caseNotes.trim(),
        enable_yara: enableYara,
        enable_ioc: enableIoc,
        enable_ocr: enableOcr,
        enable_stinger: enableStinger,
        enable_hindsight: enableHindsight,
        enable_data_carving: selectedArtifactIds.has('carve_files'),
        enable_bulk_extractor: selectedArtifactIds.has('bulk_extractor'),
        enable_vss: selectedArtifactIds.has('fs_vss'),
        max_workers: clampedWorkers,
        selected_artifacts: selectedList,
        initial_keywords: initialKeywords.map((k) => ({
          keyword: k.keyword,
          is_regex: Boolean(k.is_regex),
          case_sensitive: Boolean(k.case_sensitive),
          category: k.category || 'General',
        })),
        keywords: initialKeywords.map((k) => k.keyword),
        run_async: true,
      };

      const res = await apiClient.processCase(req);
      setStatusData({
        case_id: res.case_id,
        status: 'RUNNING',
        progress: 5,
        current_step: 'Initializing forensic evidence pipeline...',
        logs: [],
        total_logs: 0,
      });
      setActiveCaseId(res.case_id);
      setCurrentStep(4);
      onCaseCreated(res.case_id);
    } catch (err: unknown) {
      setSubmissionError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  const logs: ProcessingLog[] = statusData?.logs || [];
  const filteredLogs = logs.filter((l) => {
    if (moduleFilter !== 'ALL' && l.status !== moduleFilter) return false;
    if (logSearch) {
      const q = logSearch.toLowerCase();
      return (
        l.module_name.toLowerCase().includes(q) ||
        l.command_executed.toLowerCase().includes(q) ||
        (l.error_message && l.error_message.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const steps = [
    { num: 1, title: 'Case Details', subtitle: 'Case identifiers & acquisition profiles', icon: FileText },
    { num: 2, title: 'Evidence Sources', subtitle: 'Forensic image or folder selection', icon: Disc },
    { num: 3, title: 'Processing Options', subtitle: 'Artifact parsers & IOC keywords', icon: ListChecks },
    { num: 4, title: 'Execution Monitor', subtitle: 'Live job progress & audit logs', icon: Terminal },
  ];

  const activeCategoryObj = ARTIFACT_CATEGORIES_CATALOG.find((c) => c.category === selectedCategory);
  const activeSelectedCount = activeCategoryObj
    ? activeCategoryObj.items.filter((i) => selectedArtifactIds.has(i.id)).length
    : 0;

  return (
    <>
      <div className="flex flex-col h-full bg-[#f1f5f9] dark:bg-[#0f172a] text-[#0f172a] dark:text-[#f8fafc] overflow-hidden font-sans select-none">
        <div className="h-12 bg-white dark:bg-[#1e293b] border-b border-[#cbd5e1] dark:border-[#334155] px-4 flex items-center justify-between shrink-0 select-none">
          <div className="flex items-center gap-3">
            <span className="font-bold tracking-wider text-sm text-[#0284c7] dark:text-[#38bdf8] font-mono">
              WINDOWS FORENSIC TOOLKIT (WFT) PROCESS
            </span>
            <span className="text-slate-300 dark:text-slate-600">|</span>
            <span className="text-xs text-slate-500 dark:text-slate-400">
              Forensic Acquisition & Evidence Ingestion Workbench
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => {
                setCurrentStep(4);
                setIsLogDrawerExpanded(true);
              }}
              className="flex items-center gap-1.5 px-2.5 py-1 bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] text-slate-700 dark:text-slate-300 rounded text-xs font-semibold transition-colors shadow-2xs cursor-pointer"
              title="Open Pipeline Execution Monitor & CLI Logs"
            >
              <Terminal className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
              <span>Console / Logs</span>
            </button>

            {/* Single-Click Process Evidence Button available directly in header once source path is selected */}
            {sourcePath.trim() && currentStep !== 4 && (
              <button
                type="button"
                onClick={handleStartProcessing}
                disabled={isSubmitting || statusData?.status === 'RUNNING'}
                className="flex items-center gap-1.5 px-3.5 py-1 bg-[#166534] hover:bg-emerald-800 text-white rounded text-xs font-bold transition-colors shadow-2xs cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Process Evidence Now</span>
              </button>
            )}

            {onNavigateToExamine && (
              <button
                onClick={onNavigateToExamine}
                className="flex items-center gap-1.5 px-3 py-1 bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] text-[#0284c7] dark:text-[#38bdf8] rounded text-xs font-semibold transition-colors shadow-2xs cursor-pointer"
              >
                <Eye className="w-3.5 h-3.5" />
                <span>Go to Examine</span>
              </button>
            )}
            {isOpenAsModal && onCloseModal && (
              <button
                onClick={onCloseModal}
                className="p-1 hover:bg-slate-100 dark:hover:bg-[#334155] rounded text-slate-500 hover:text-[#0f172a] dark:hover:text-white transition-colors cursor-pointer"
                title="Close Wizard"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        <div className="flex-1 flex overflow-hidden">
          <div className="w-64 bg-white dark:bg-[#1e293b] border-r border-[#cbd5e1] dark:border-[#334155] flex flex-col justify-between shrink-0 select-none p-4">
            <div className="space-y-6">
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 font-mono">
                Workflow Steps
              </div>

              <div className="space-y-2">
                {steps.map((st) => {
                  const isActive = currentStep === st.num;
                  const isPassed = currentStep > st.num;

                  return (
                    <button
                      key={st.num}
                      onClick={() => setCurrentStep(st.num)}
                      className={`w-full flex items-start gap-3 p-2.5 rounded text-left transition-all cursor-pointer border ${
                        isActive
                          ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] border-[#0284c7] dark:border-[#38bdf8] text-[#0f172a] dark:text-[#f8fafc] font-bold shadow-2xs'
                          : isPassed
                          ? 'bg-slate-50 dark:bg-[#0f172a] hover:bg-slate-100 dark:hover:bg-[#334155] border-[#cbd5e1] dark:border-[#334155] text-slate-700 dark:text-slate-300'
                          : 'bg-transparent hover:bg-slate-100 dark:hover:bg-[#0f172a]/40 border-transparent text-slate-400 dark:text-slate-500'
                      }`}
                    >
                      <div
                        className={`w-6 h-6 rounded flex items-center justify-center shrink-0 text-xs font-mono font-bold transition-colors ${
                          isActive
                            ? 'bg-[#0284c7] text-white'
                            : isPassed
                            ? 'bg-slate-200 dark:bg-[#1e293b] text-slate-700 dark:text-slate-300 border border-[#cbd5e1] dark:border-[#334155]'
                            : 'bg-slate-100 dark:bg-[#0f172a] text-slate-400 dark:text-slate-500 border border-[#cbd5e1] dark:border-[#334155]'
                        }`}
                      >
                        {isPassed ? <Check className="w-3.5 h-3.5 stroke-[3]" /> : st.num}
                      </div>

                      <div className="min-w-0 flex-1 pt-0.5">
                        <div className={`text-xs font-bold leading-tight ${isActive ? 'text-[#0f172a] dark:text-[#f8fafc]' : 'text-slate-700 dark:text-slate-300'}`}>
                          {st.title}
                        </div>
                        <div className="text-[10px] text-slate-500 dark:text-slate-400 truncate mt-0.5 font-sans">
                          {st.subtitle}
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="p-3 bg-slate-50 dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded text-[11px] space-y-1.5 font-mono">
              <div className="text-slate-500 dark:text-slate-400 flex justify-between">
                <span>Target:</span>
                <span className="text-[#0284c7] dark:text-[#38bdf8] font-bold uppercase truncate max-w-[120px]">
                  {sourceType === 'folder' ? 'Folder' : 'Disk Image'}
                </span>
              </div>
              <div className="text-slate-500 dark:text-slate-400 flex justify-between">
                <span>Artifacts:</span>
                <span className="text-[#0f172a] dark:text-[#f8fafc] font-semibold">{selectedCatalogCount} Selected</span>
              </div>
              <div className="text-slate-500 dark:text-slate-400 flex justify-between">
                <span>Threads:</span>
                <span className="text-[#0284c7] dark:text-[#38bdf8] font-bold">{maxWorkers} Workers</span>
              </div>
              <div className="text-slate-500 dark:text-slate-400 flex justify-between">
                <span>VSS/Carve/BE:</span>
                <span className="text-[#0f172a] dark:text-[#f8fafc] font-semibold">
                  {[enableVss && 'VSS', enableDataCarving && 'Carve', enableBulkExtractor && 'BE'].filter(Boolean).join('+') || 'Off'}
                </span>
              </div>
              <div className="text-slate-500 dark:text-slate-400 flex justify-between">
                <span>Keywords:</span>
                <span className="text-[#0f172a] dark:text-[#f8fafc] font-semibold">{initialKeywords.length} Staged</span>
              </div>
              <div className="text-slate-500 dark:text-slate-400 flex justify-between">
                <span>Threat YARA:</span>
                <span className={enableYara ? 'text-[#166534] dark:text-emerald-400 font-bold' : 'text-slate-400'}>{enableYara ? 'Enabled' : 'Off'}</span>
              </div>
              <div className="text-slate-500 dark:text-slate-400 flex justify-between">
                <span>Optical OCR:</span>
                <span className={enableOcr ? 'text-[#166534] dark:text-emerald-400 font-bold' : 'text-slate-400'}>{enableOcr ? 'Enabled' : 'Off'}</span>
              </div>
            </div>
          </div>

          <div className="flex-1 flex flex-col overflow-hidden bg-[#f1f5f9] dark:bg-[#0f172a]">
            {submissionError && currentStep !== 4 && (
              <div className="mx-8 mt-4 p-2.5 badge-status-error text-xs flex items-center justify-between gap-2 rounded shrink-0">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-[#991b1b]" />
                  <span>{submissionError}</span>
                </div>
                <button type="button" onClick={() => setSubmissionError(null)} className="p-0.5 hover:opacity-80 cursor-pointer">
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
            {currentStep === 1 && (
              <div className="flex-1 overflow-y-auto p-8 max-w-4xl space-y-6">
                <div>
                  <h2 className="text-lg font-bold text-[#0f172a] dark:text-[#f8fafc] flex items-center gap-2">
                    <FileText className="w-5 h-5 text-[#0284c7] dark:text-[#38bdf8]" />
                    <span>Case Details & DFIR Acquisition Profile</span>
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                    Configure forensic case identifiers, examiner metadata, and select pre-tuned investigative profiles.
                  </p>
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 font-mono">
                    Quick Investigative Presets
                  </label>
                  <div className="grid grid-cols-3 content-start auto-rows-max items-start gap-3">
                    <button
                      type="button"
                      onClick={() => applyPreset('quick')}
                      className={`p-3 bg-white dark:bg-[#1e293b] hover:bg-slate-50 dark:hover:bg-[#334155] border rounded text-left transition-colors cursor-pointer group shadow-2xs ${
                        selectedPreset === 'quick'
                          ? 'border-[#0284c7] dark:border-[#38bdf8]'
                          : 'border-[#cbd5e1] dark:border-[#334155] hover:border-[#0284c7] dark:hover:border-[#38bdf8]'
                      }`}
                    >
                      <div className="text-xs font-bold text-[#0f172a] dark:text-[#f8fafc] group-hover:text-[#0284c7] dark:group-hover:text-[#38bdf8] flex items-center justify-between">
                        <span>Quick Triage</span>
                        <Zap className="w-3.5 h-3.5 text-slate-400 group-hover:text-[#0284c7] dark:group-hover:text-[#38bdf8]" />
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                        Event Logs, Prefetch, LNK, USB, Browser History, RECmd & AutoRuns. Skips heavy VSS/Carving/BE.
                      </div>
                    </button>

                    <button
                      type="button"
                      onClick={() => applyPreset('comprehensive')}
                      className={`p-3 bg-white dark:bg-[#1e293b] hover:bg-slate-50 dark:hover:bg-[#334155] border rounded text-left transition-colors cursor-pointer group shadow-2xs ${
                        selectedPreset === 'comprehensive'
                          ? 'border-[#0284c7] dark:border-[#38bdf8]'
                          : 'border-[#cbd5e1] dark:border-[#334155] hover:border-[#0284c7] dark:hover:border-[#38bdf8]'
                      }`}
                    >
                      <div className="text-xs font-bold text-[#0284c7] dark:text-[#38bdf8] flex items-center justify-between">
                        <span>Comprehensive IR</span>
                        <Cpu className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
                      </div>
                      <div className="text-[11px] text-slate-600 dark:text-slate-300 mt-1">
                        All 43 options: 16 EZ Tools, SQLECmd, VSS, Data Carving, Bulk Extractor, Browsers, YARA-X, Stinger & OCR.
                      </div>
                    </button>

                    <button
                      type="button"
                      onClick={() => applyPreset('malware')}
                      className={`p-3 bg-white dark:bg-[#1e293b] hover:bg-slate-50 dark:hover:bg-[#334155] border rounded text-left transition-colors cursor-pointer group shadow-2xs ${
                        selectedPreset === 'malware'
                          ? 'border-[#0284c7] dark:border-[#38bdf8]'
                          : 'border-[#cbd5e1] dark:border-[#334155] hover:border-[#0284c7] dark:hover:border-[#38bdf8]'
                      }`}
                    >
                      <div className="text-xs font-bold text-[#0f172a] dark:text-[#f8fafc] group-hover:text-[#0284c7] dark:group-hover:text-[#38bdf8] flex items-center justify-between">
                        <span>Threat Hunting</span>
                        <Shield className="w-3.5 h-3.5 text-slate-400 group-hover:text-[#0284c7] dark:group-hover:text-[#38bdf8]" />
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                        YARA-X, Trellix Stinger, Bulk Extractor IOCs, Hindsight, BAM/DAM, Tasks & Registry persistence.
                      </div>
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-2 content-start auto-rows-max items-start gap-4">
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Case Name / Directory Stem *</label>
                    <input
                      type="text"
                      value={caseName}
                      onChange={(e) => setCaseName(e.target.value)}
                      placeholder="e.g. Incident_20261031_01"
                      className="w-full bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded px-3 py-2 text-xs text-[#0f172a] dark:text-[#f8fafc] font-mono focus:border-[#0284c7] focus:outline-none"
                      required
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Case Number / Incident Ticket</label>
                    <input
                      type="text"
                      value={caseNumber}
                      onChange={(e) => setCaseNumber(e.target.value)}
                      placeholder="e.g. DFIR-2026-0891"
                      className="w-full bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded px-3 py-2 text-xs text-[#0f172a] dark:text-[#f8fafc] font-mono focus:border-[#0284c7] focus:outline-none"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Primary Examiner</label>
                    <input
                      type="text"
                      value={examinerName}
                      onChange={(e) => setExaminerName(e.target.value)}
                      placeholder="e.g. Senior DFIR Specialist"
                      className="w-full bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded px-3 py-2 text-xs text-[#0f172a] dark:text-[#f8fafc] font-mono focus:border-[#0284c7] focus:outline-none"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Target Case / Output Folder</label>
                      <button
                        type="button"
                        onClick={() => openInAppBrowser('storage', 'folder')}
                        className="flex items-center gap-1.5 px-2.5 py-0.5 bg-[#0284c7] hover:bg-[#0369a1] text-white rounded text-[11px] font-semibold transition-colors cursor-pointer shadow-2xs"
                      >
                        <FolderOpen className="w-3.5 h-3.5" />
                        <span>Browse Folder...</span>
                      </button>
                    </div>
                    <input
                      type="text"
                      value={targetStorageDir}
                      onChange={(e) => setTargetStorageDir(e.target.value.replace(/^["']|["']$/g, ''))}
                      placeholder="Optional — defaults to isolated WFT Cases folder (CASES_DIR/<case_id>)"
                      className={`w-full bg-white dark:bg-[#1e293b] border rounded px-3 py-2 text-xs text-[#0f172a] dark:text-[#f8fafc] font-mono focus:outline-none ${
                        isTargetSameAsSource
                          ? 'border-red-500 focus:border-red-600'
                          : 'border-[#cbd5e1] dark:border-[#334155] focus:border-[#0284c7]'
                      }`}
                    />
                    {isTargetSameAsSource && (
                      <p className="text-[11px] text-[#991b1b] dark:text-red-400 font-semibold">
                        Target Case / Output Folder must not be the same as the Evidence Source path.
                      </p>
                    )}
                  </div>

                  <div className="col-span-2 space-y-1.5">
                    <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Case Notes / Forensic Scope</label>
                    <textarea
                      rows={2}
                      value={caseNotes}
                      onChange={(e) => setCaseNotes(e.target.value)}
                      placeholder="Provide evidence intake context, suspected malware beacons, user accounts of interest, etc."
                      className="w-full bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded px-3 py-2 text-xs text-[#0f172a] dark:text-[#f8fafc] font-mono focus:border-[#0284c7] focus:outline-none"
                    />
                  </div>
                </div>
              </div>
            )}

            {currentStep === 2 && (
              <div className="flex-1 overflow-y-auto p-8 max-w-4xl space-y-6">
                <div>
                  <h2 className="text-lg font-bold text-[#0f172a] dark:text-[#f8fafc] flex items-center gap-2">
                    <Disc className="w-5 h-5 text-[#0284c7] dark:text-[#38bdf8]" />
                    <span>Evidence Source Selection</span>
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                    Select an evidence folder/directory or a forensic disk image (.E01, .VHDX, .RAW), then click <strong>Process Evidence</strong> below to start immediately.
                  </p>
                </div>

                <div className="space-y-4 p-5 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded">
                  <div className="flex flex-wrap items-center gap-3 pt-1">
                    <button
                      type="button"
                      onClick={() => {
                        setSourceType('folder');
                        openInAppBrowser('evidence', 'folder');
                      }}
                      className="flex items-center gap-2 px-4 py-2 bg-[#0284c7] hover:bg-[#0369a1] text-white rounded text-xs font-bold transition-all border border-[#0369a1] shadow-2xs cursor-pointer"
                    >
                      <FolderOpen className="w-4 h-4" />
                      <span>Browse Folder...</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => {
                        setSourceType('image');
                        openInAppBrowser('evidence', 'file');
                      }}
                      className="flex items-center gap-2 px-4 py-2 bg-white dark:bg-[#0f172a] hover:bg-slate-50 dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc] rounded text-xs font-bold transition-all shadow-2xs cursor-pointer"
                    >
                      <Disc className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
                      <span>Browse Disk Image...</span>
                    </button>
                  </div>

                  <div className="space-y-2 pt-1">
                    <div className="flex items-center justify-between">
                      <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                        Evidence Path:
                      </label>
                      {isValidatingPath && (
                        <span className="text-[11px] text-[#0284c7] dark:text-[#38bdf8] flex items-center gap-1 font-mono">
                          <RefreshCw className="w-3 h-3 animate-spin" />
                          <span>Validating source on disk...</span>
                        </span>
                      )}
                    </div>

                    <input
                      type="text"
                      value={sourcePath}
                      onChange={(e) => {
                        const val = e.target.value.replace(/^["']|["']$/g, '');
                        setSourcePath(val);
                      }}
                      placeholder="e.g. C:\Evidence\TriageFolder or D:\Forensics\evidence_disk.E01"
                      className="w-full bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded px-3 py-2 text-xs text-[#0f172a] dark:text-[#f8fafc] font-mono focus:border-[#0284c7] focus:outline-none"
                    />

                    {isTargetSameAsSource && (
                      <div className="p-2.5 rounded badge-status-error text-xs flex items-center gap-2 font-mono">
                        <AlertTriangle className="w-4 h-4 shrink-0" />
                        <span>Target Case / Output Folder must not be the same as the Evidence Source path.</span>
                      </div>
                    )}

                    {pathValidation && pathValidation.valid && (
                      <div className="p-3 rounded badge-status-success text-xs flex items-center justify-between font-mono">
                        <div className="flex items-center gap-2.5">
                          <CheckCircle2 className="w-5 h-5 shrink-0" />
                          <div>
                            <span className="font-bold">
                              {pathValidation.is_dir
                                ? '✓ Valid Evidence Folder Verified on Disk'
                                : '✓ Valid Disk Image Verified on Disk'}
                            </span>
                            <span className="text-[11px] block mt-0.5 opacity-90">
                              {pathValidation.detected_type} {pathValidation.formatted_size ? `• File Size: ${pathValidation.formatted_size}` : ''}
                            </span>
                          </div>
                        </div>
                        <span className="text-[10px] px-2 py-0.5 rounded border font-semibold uppercase tracking-wider">
                          VERIFIED
                        </span>
                      </div>
                    )}

                    {pathValidation && !pathValidation.valid && sourcePath.trim() && (
                      <div className="p-2.5 rounded badge-status-error text-xs flex items-center gap-2.5 font-mono">
                        <XCircle className="w-4 h-4 shrink-0" />
                        <div>
                          <span className="font-bold">Path not found on disk</span>
                          <span className="text-[11px] block mt-0.5 opacity-90">
                            {pathValidation.error || 'Ensure the file or folder exists and is accessible.'}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {currentStep === 3 && (
              <div className="flex-1 flex flex-col overflow-hidden">
                <div className="p-3 px-4 border-b border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] flex items-center justify-between shrink-0">
                  <div className="flex items-center gap-4">
                    <div>
                      <h2 className="text-base font-bold text-[#0f172a] dark:text-[#f8fafc] flex items-center gap-2">
                        <ListChecks className="w-5 h-5 text-[#0284c7] dark:text-[#38bdf8]" />
                        <span>Processing Options & Artifacts</span>
                      </h2>
                    </div>

                    <div className="flex items-center gap-1 bg-[#f1f5f9] dark:bg-[#0f172a] p-0.5 rounded border border-[#cbd5e1] dark:border-[#334155]">
                      <button
                        type="button"
                        onClick={() => setStep3SubTab('artifacts')}
                        className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-semibold transition-colors cursor-pointer ${
                          step3SubTab === 'artifacts'
                            ? 'bg-[#0284c7] text-white border border-[#0369a1] shadow-2xs'
                            : 'text-slate-600 dark:text-slate-400 hover:text-[#0f172a] dark:hover:text-[#f8fafc]'
                        }`}
                      >
                        <ListChecks className="w-3.5 h-3.5" />
                        <span>Artifact Selection ({selectedCatalogCount})</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => setStep3SubTab('keywords')}
                        className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-semibold transition-colors cursor-pointer ${
                          step3SubTab === 'keywords'
                            ? 'bg-[#0284c7] text-white border border-[#0369a1] shadow-2xs'
                            : 'text-slate-600 dark:text-slate-400 hover:text-[#0f172a] dark:hover:text-[#f8fafc]'
                        }`}
                      >
                        <Hash className="w-3.5 h-3.5" />
                        <span>Keyword Lists to Search ({initialKeywords.length})</span>
                      </button>
                    </div>
                  </div>

                  {step3SubTab === 'artifacts' && (
                    <div className="flex items-center gap-3">
                      <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-slate-100 dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] text-xs">
                        <Cpu className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
                        <label htmlFor="wft-max-workers-input" className="text-slate-600 dark:text-slate-400 font-medium">Worker Threads:</label>
                        <input
                          type="range"
                          min={1}
                          max={32}
                          value={maxWorkers}
                          onChange={(e) => setMaxWorkers(Math.max(1, Math.min(32, Number(e.target.value) || 25)))}
                          aria-label="Multi-Threading Worker Threads Slider"
                          className="w-20 accent-[#0284c7] cursor-pointer"
                        />
                        <input
                          id="wft-max-workers-input"
                          data-testid="max-workers-input"
                          type="number"
                          min={1}
                          max={32}
                          value={maxWorkers}
                          onChange={(e) => setMaxWorkers(Math.max(1, Math.min(32, Number(e.target.value) || 1)))}
                          className="w-12 px-1 py-0.5 text-xs font-mono font-bold text-center bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded text-[#0284c7] dark:text-[#38bdf8]"
                        />
                      </div>
                      <button
                        type="button"
                        onClick={() => toggleAllGlobally(true)}
                        className="px-2.5 py-1 text-xs rounded bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#334155] text-slate-700 dark:text-slate-300 border border-[#cbd5e1] dark:border-[#334155] transition-colors cursor-pointer"
                      >
                        Select All
                      </button>
                      <button
                        type="button"
                        onClick={() => toggleAllGlobally(false)}
                        className="px-2.5 py-1 text-xs rounded bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#334155] text-slate-700 dark:text-slate-300 border border-[#cbd5e1] dark:border-[#334155] transition-colors cursor-pointer"
                      >
                        Deselect All
                      </button>
                    </div>
                  )}
                </div>

                {step3SubTab === 'keywords' ? (
                  <div className="flex-1 overflow-hidden p-4 bg-[#f1f5f9] dark:bg-[#0f172a]">
                    <div className="h-full border border-[#cbd5e1] dark:border-[#334155] rounded overflow-hidden bg-white dark:bg-[#1e293b] shadow-2xs flex flex-col">
                      <KeywordManager
                        caseId=""
                        localStagingMode={true}
                        stagedKeywords={initialKeywords}
                        onStagedKeywordsChange={setInitialKeywords}
                        isModal={false}
                      />
                    </div>
                  </div>
                ) : (
                  <div ref={step3ContainerRef} className="flex-1 flex overflow-hidden relative">
                    <div
                      style={{ width: `${step3Left.width}px` }}
                      className="bg-white dark:bg-[#1e293b] border-r border-[#cbd5e1] dark:border-[#334155] overflow-y-auto p-2 space-y-1 select-none shrink-0"
                    >
                      {ARTIFACT_CATEGORIES_CATALOG.map((cat) => {
                        const isSelected = selectedCategory === cat.category;
                        const catSelectedCount = cat.items.filter((i) => selectedArtifactIds.has(i.id)).length;
                        const totalInCat = cat.items.length;

                        return (
                          <button
                            key={cat.category}
                            type="button"
                            onClick={() => setSelectedCategory(cat.category)}
                            className={`w-full p-2 rounded flex items-center justify-between text-left transition-colors cursor-pointer border ${
                              isSelected
                                ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0f172a] dark:text-[#f8fafc] font-bold border-[#0284c7] dark:border-[#38bdf8] shadow-2xs'
                                : 'text-[#0f172a] dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-[#334155] border-transparent'
                            }`}
                          >
                            <span className="text-xs truncate">{cat.category}</span>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border bg-slate-100 dark:bg-[#0f172a]">
                              {catSelectedCount}/{totalInCat}
                            </span>
                          </button>
                        );
                      })}
                    </div>

                    <ResizeHandle
                      orientation="vertical"
                      onMouseDown={step3Left.handleMouseDown}
                      onDoubleClick={step3Left.resetWidth}
                      isDragging={step3Left.isDragging}
                    />

                    <div className="flex-1 overflow-y-auto p-6 bg-[#f1f5f9] dark:bg-[#0f172a] space-y-4 min-w-0">
                      {/* Integrated Forensic & Threat Engines rendered ONLY in 'Malware & Threat Hunting' */}
                      {selectedCategory === 'Malware & Threat Hunting' && (
                        <div className="p-4 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] space-y-3 shadow-2xs">
                          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-600 dark:text-slate-300 font-mono">
                            Integrated Forensic & Threat Engines
                          </div>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                            <label className="flex items-center justify-between p-2 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a] cursor-pointer">
                              <span className="font-semibold text-[#0f172a] dark:text-[#f8fafc]">Enable YARA-X Malware Scanning</span>
                              <input
                                type="checkbox"
                                checked={enableYara}
                                onChange={(e) => handleEngineSwitchChange('yara', e.target.checked)}
                                className="rounded border-[#cbd5e1] text-[#0284c7] focus:ring-0 w-4 h-4 cursor-pointer"
                              />
                            </label>

                            <label className="flex items-center justify-between p-2 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a] cursor-pointer">
                              <span className="font-semibold text-[#0f172a] dark:text-[#f8fafc]">Enable IOC & Entity Correlation</span>
                              <input
                                type="checkbox"
                                checked={enableIoc}
                                onChange={(e) => handleEngineSwitchChange('ioc', e.target.checked)}
                                className="rounded border-[#cbd5e1] text-[#0284c7] focus:ring-0 w-4 h-4 cursor-pointer"
                              />
                            </label>

                            <label className="flex items-center justify-between p-2 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a] cursor-pointer">
                              <span className="font-semibold text-[#0f172a] dark:text-[#f8fafc]">Enable Trellix Stinger</span>
                              <input
                                type="checkbox"
                                checked={enableStinger}
                                onChange={(e) => handleEngineSwitchChange('stinger', e.target.checked)}
                                className="rounded border-[#cbd5e1] text-[#0284c7] focus:ring-0 w-4 h-4 cursor-pointer"
                              />
                            </label>

                            <label className="flex items-center justify-between p-2 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a] cursor-pointer">
                              <span className="font-semibold text-[#0f172a] dark:text-[#f8fafc]">Enable Hindsight</span>
                              <input
                                type="checkbox"
                                checked={enableHindsight}
                                onChange={(e) => handleEngineSwitchChange('hindsight', e.target.checked)}
                                className="rounded border-[#cbd5e1] text-[#0284c7] focus:ring-0 w-4 h-4 cursor-pointer"
                              />
                            </label>

                            <label className="flex items-center justify-between p-2 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a] cursor-pointer md:col-span-2">
                              <span className="font-semibold text-[#0f172a] dark:text-[#f8fafc]">Enable RapidOCR Text Extraction</span>
                              <input
                                type="checkbox"
                                checked={enableOcr}
                                onChange={(e) => handleEngineSwitchChange('ocr', e.target.checked)}
                                className="rounded border-[#cbd5e1] text-[#0284c7] focus:ring-0 w-4 h-4 cursor-pointer"
                              />
                            </label>
                          </div>
                        </div>
                      )}

                      {/* Hidden DOM inputs keeping checkboxes accessible for unselected categories / engines */}
                      {selectedCategory !== 'Recovery, Carving & Bulk Extractor' && (
                        <div className="hidden" aria-hidden="true" style={{ display: 'none' }}>
                          {ARTIFACT_CATEGORIES_CATALOG.find((c) => c.category === 'Recovery, Carving & Bulk Extractor')?.items.map((item) => {
                            const isChecked = selectedArtifactIds.has(item.id);
                            return (
                              <input
                                key={item.id}
                                type="checkbox"
                                data-testid={`artifact-checkbox-${item.id}`}
                                checked={isChecked}
                                onChange={() => toggleArtifact(item.id)}
                                className="hidden"
                              />
                            );
                          })}
                        </div>
                      )}
                      {selectedCategory !== 'Malware & Threat Hunting' && (
                        <div className="hidden" aria-hidden="true" style={{ display: 'none' }}>
                          <label>
                            Enable YARA-X Malware Scanning
                            <input
                              type="checkbox"
                              checked={enableYara}
                              onChange={(e) => handleEngineSwitchChange('yara', e.target.checked)}
                            />
                          </label>
                          <label>
                            Enable Trellix Stinger
                            <input
                              type="checkbox"
                              checked={enableStinger}
                              onChange={(e) => handleEngineSwitchChange('stinger', e.target.checked)}
                            />
                          </label>
                          <label>
                            Enable IOC & Entity Correlation
                            <input
                              type="checkbox"
                              checked={enableIoc}
                              onChange={(e) => handleEngineSwitchChange('ioc', e.target.checked)}
                            />
                          </label>
                          <label>
                            Enable Hindsight
                            <input
                              type="checkbox"
                              checked={enableHindsight}
                              onChange={(e) => handleEngineSwitchChange('hindsight', e.target.checked)}
                            />
                          </label>
                          <label>
                            Enable RapidOCR Text Extraction
                            <input
                              type="checkbox"
                              checked={enableOcr}
                              onChange={(e) => handleEngineSwitchChange('ocr', e.target.checked)}
                            />
                          </label>
                          {ARTIFACT_CATEGORIES_CATALOG.find((c) => c.category === 'Malware & Threat Hunting')?.items.map((item) => {
                            const isChecked = selectedArtifactIds.has(item.id);
                            return (
                              <input
                                key={item.id}
                                type="checkbox"
                                data-testid={`artifact-checkbox-${item.id}`}
                                checked={isChecked}
                                onChange={() => toggleArtifact(item.id)}
                                className="hidden"
                              />
                            );
                          })}
                        </div>
                      )}

                      {activeCategoryObj && (
                        <>
                          <div className="flex items-center justify-between border-b border-[#cbd5e1] dark:border-[#334155] pb-3">
                            <div>
                              <h3 className="text-sm font-bold text-[#0f172a] dark:text-[#f8fafc]">{activeCategoryObj.category}</h3>
                              <span className="text-xs text-slate-500 font-mono">
                                {activeSelectedCount} of {activeCategoryObj.items.length} artifacts active
                              </span>
                            </div>

                            <div className="flex items-center gap-2">
                              <button
                                type="button"
                                onClick={() => toggleCategoryAll(activeCategoryObj.category, true)}
                                className="text-[11px] text-[#0284c7] dark:text-[#38bdf8] hover:underline cursor-pointer font-semibold"
                              >
                                Select Category
                              </button>
                              <span className="text-slate-300 dark:text-slate-600">|</span>
                              <button
                                type="button"
                                onClick={() => toggleCategoryAll(activeCategoryObj.category, false)}
                                className="text-[11px] text-slate-500 hover:underline cursor-pointer"
                              >
                                Deselect Category
                              </button>
                            </div>
                          </div>

                          <div className="space-y-2">
                            {activeCategoryObj.items.map((item) => {
                              const isChecked = selectedArtifactIds.has(item.id);
                              return (
                                <label
                                  key={item.id}
                                  className={`p-3 rounded border flex items-start gap-3 cursor-pointer select-none transition-colors ${
                                    isChecked
                                      ? 'bg-white dark:bg-[#1e293b] border-[#0284c7] dark:border-[#38bdf8]'
                                      : 'bg-white/60 dark:bg-[#1e293b]/60 border-[#cbd5e1] dark:border-[#334155] text-slate-500'
                                  }`}
                                >
                                  <input
                                    type="checkbox"
                                    data-testid={`artifact-checkbox-${item.id}`}
                                    checked={isChecked}
                                    onChange={() => toggleArtifact(item.id)}
                                    className="mt-0.5 rounded border-[#cbd5e1] text-[#0284c7] focus:ring-0 w-4 h-4 cursor-pointer"
                                  />
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2">
                                      <span className={`text-xs font-bold ${isChecked ? 'text-[#0f172a] dark:text-[#f8fafc]' : 'text-slate-500'}`}>
                                        {item.name}
                                      </span>
                                      <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-100 dark:bg-[#0f172a] text-[#0284c7] dark:text-[#38bdf8] border border-[#cbd5e1] dark:border-[#334155]">
                                        {item.tool}
                                      </span>
                                    </div>
                                    <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 leading-snug">{item.desc}</p>
                                  </div>
                                </label>
                              );
                            })}
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}

            {currentStep === 4 && (
              <div className="flex-1 flex flex-col overflow-hidden p-6 space-y-4">
                <div className="p-4 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded space-y-3 shadow-2xs">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className="text-base font-bold text-[#0f172a] dark:text-[#f8fafc]">{caseName}</span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                          statusData?.status === 'SUCCESS' || statusData?.status === 'COMPLETED'
                            ? 'badge-status-success'
                            : statusData?.status === 'RUNNING'
                            ? 'badge-status-running'
                            : statusData?.status === 'FAILED' || statusData?.status === 'ERROR'
                            ? 'badge-status-error'
                            : 'badge-status-neutral'
                        }`}
                      >
                        {statusData?.status || 'IDLE'}
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      {statusData?.status !== 'RUNNING' && (
                        <button
                          type="button"
                          onClick={handleStartProcessing}
                          disabled={isSubmitting}
                          className="px-3.5 py-1.5 bg-[#0284c7] hover:bg-[#0369a1] disabled:opacity-50 text-white rounded text-xs font-semibold flex items-center gap-1.5 border border-[#0369a1] shadow-2xs transition-colors cursor-pointer"
                        >
                          <RefreshCw className="w-3.5 h-3.5" />
                          <span>Re-Run Pipeline</span>
                        </button>
                      )}

                      {onNavigateToExamine && (
                        <button
                          type="button"
                          onClick={onNavigateToExamine}
                          className="px-3 py-1.5 bg-white dark:bg-[#0f172a] hover:bg-slate-50 dark:hover:bg-[#334155] text-[#0284c7] dark:text-[#38bdf8] rounded text-xs font-semibold flex items-center gap-1.5 border border-[#cbd5e1] dark:border-[#334155] transition-colors cursor-pointer"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>View in Examine</span>
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="space-y-1">
                    <div className="flex justify-between text-xs font-mono text-slate-500 dark:text-slate-400">
                      <span className="truncate max-w-[500px]">
                        {statusData?.current_step || 'Processing evidence...'}
                      </span>
                      <span className="font-bold text-[#0284c7] dark:text-[#38bdf8]">{statusData?.progress || 0}%</span>
                    </div>

                    <div className="w-full bg-[#f1f5f9] dark:bg-[#0f172a] rounded h-2 overflow-hidden border border-[#cbd5e1] dark:border-[#334155]">
                      <div
                        className={`h-full transition-all duration-300 rounded ${
                          statusData?.status === 'FAILED' || statusData?.status === 'ERROR'
                            ? 'bg-[#991b1b]'
                            : statusData?.status === 'SUCCESS' || statusData?.status === 'COMPLETED'
                            ? 'bg-[#166534]'
                            : 'bg-[#0284c7] dark:bg-[#38bdf8]'
                        }`}
                        style={{ width: `${statusData?.progress || 0}%` }}
                      />
                    </div>
                  </div>

                  {(submissionError || statusData?.error) && (
                    <div className="p-2.5 badge-status-error text-xs flex items-center gap-2 rounded">
                      <AlertTriangle className="w-4 h-4 shrink-0 text-[#991b1b]" />
                      <span>{submissionError || statusData?.error}</span>
                    </div>
                  )}
                </div>

                <div className="flex-1 flex flex-col bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded overflow-hidden">
                  <div className="p-3 border-b border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a] flex items-center justify-between shrink-0">
                    <div className="flex items-center gap-2 text-xs font-bold text-[#0f172a] dark:text-[#f8fafc] uppercase font-mono">
                      <Activity className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
                      <span>Module Execution Status Table</span>
                      <span className="text-slate-500 font-normal">({filteredLogs.length} events logged)</span>
                    </div>

                    <div className="flex items-center gap-2">
                      <div className="relative">
                        <Search className="w-3 h-3 absolute left-2.5 top-2.5 text-slate-400" />
                        <input
                          type="text"
                          value={logSearch}
                          onChange={(e) => setLogSearch(e.target.value)}
                          placeholder="Search module logs..."
                          className="bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc] text-xs rounded pl-8 pr-3 py-1 font-mono focus:outline-none focus:border-[#0284c7] w-48"
                        />
                      </div>

                      <select
                        value={moduleFilter}
                        onChange={(e) => setModuleFilter(e.target.value)}
                        className="bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc] text-xs rounded px-2.5 py-1 font-mono focus:outline-none focus:border-[#0284c7]"
                      >
                        <option value="ALL">All Status</option>
                        <option value="SUCCESS">Success Only</option>
                        <option value="ERROR">Errors Only</option>
                      </select>

                      <button
                        type="button"
                        onClick={() => setIsLogDrawerExpanded(!isLogDrawerExpanded)}
                        className="px-2.5 py-1 rounded bg-white dark:bg-[#1e293b] hover:bg-slate-50 dark:hover:bg-[#334155] text-slate-700 dark:text-slate-300 border border-[#cbd5e1] dark:border-[#334155] text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
                        title={isLogDrawerExpanded ? 'Collapse CLI Drawer' : 'Expand CLI Drawer'}
                      >
                        <Terminal className="w-3.5 h-3.5" />
                        <span>Console / Logs</span>
                      </button>
                    </div>
                  </div>

                  <div className="flex-1 overflow-y-auto">
                    {filteredLogs.length === 0 ? (
                      <div className="p-8 text-center text-slate-500 text-xs italic">
                        Executing pipeline modules... Logs will appear here live.
                      </div>
                    ) : (
                      <table className="w-full text-left text-xs border-collapse">
                        <thead className="bg-[#f1f5f9] dark:bg-[#0f172a] text-slate-600 dark:text-slate-400 text-[11px] font-mono sticky top-0 border-b border-[#cbd5e1] dark:border-[#334155] select-none">
                          <tr>
                            <th className="py-2 px-3 font-semibold">Module / Tool</th>
                            <th className="py-2 px-3 font-semibold">Command Executed</th>
                            <th className="py-2 px-3 font-semibold">Status</th>
                            <th className="py-2 px-3 font-semibold">Duration</th>
                            <th className="py-2 px-3 font-semibold">Rows Ingested</th>
                            <th className="py-2 px-3 font-semibold">Timestamp (UTC)</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#e2e8f0] dark:divide-[#334155] font-sans">
                          {filteredLogs.map((log) => (
                            <tr key={log.log_id} className="hover:bg-slate-50 dark:hover:bg-[#334155]/50 transition-colors">
                              <td className="py-2 px-3 font-mono font-bold text-[#0f172a] dark:text-[#f8fafc]">
                                {log.module_name}
                              </td>
                              <td className="py-2 px-3 font-mono text-slate-500 dark:text-slate-400 truncate max-w-xs" title={log.command_executed}>
                                {log.command_executed}
                              </td>
                              <td className="py-2 px-3">
                                <span
                                  className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                                    log.status === 'SUCCESS'
                                      ? 'badge-status-success'
                                      : log.status === 'ERROR'
                                      ? 'badge-status-error'
                                      : 'badge-status-running'
                                  }`}
                                >
                                  {log.status}
                                </span>
                              </td>
                              <td className="py-2 px-3 font-mono text-slate-700 dark:text-slate-300">
                                {log.duration_ms}ms
                              </td>
                              <td className="py-2 px-3 font-mono font-bold text-[#0284c7] dark:text-[#38bdf8]">
                                {log.rows_ingested.toLocaleString()}
                              </td>
                              <td className="py-2 px-3 font-mono text-slate-500 text-[11px]">
                                {log.timestamp_utc ? log.timestamp_utc.slice(11, 19) : ''}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>

                  {isLogDrawerExpanded && (
                    <div className="h-48 border-t border-[#cbd5e1] dark:border-[#334155] bg-slate-50 dark:bg-[#0f172a] p-3 font-mono text-xs overflow-y-auto space-y-1">
                      <div className="text-slate-500 dark:text-slate-400 text-[11px] font-bold uppercase pb-1 border-b border-[#cbd5e1] dark:border-[#334155] flex justify-between">
                        <span>Subprocess Terminal Output</span>
                        <span>Exit Codes & Diagnostics</span>
                      </div>
                      {filteredLogs.map((l) => (
                        <div key={l.log_id} className="text-slate-600 dark:text-slate-400">
                          <span className="text-[#0284c7] dark:text-[#38bdf8]">[{l.module_name}]</span>{' '}
                          <span className="text-slate-800 dark:text-slate-200">$ {l.command_executed}</span>{' '}
                          <span className={l.exit_code === 0 ? 'text-[#166534] dark:text-emerald-400' : 'text-[#991b1b] dark:text-red-400'}>
                            (Exit: {l.exit_code}, {l.duration_ms}ms)
                          </span>
                          {l.error_message && (
                            <div className="text-[#991b1b] dark:text-red-400 pl-4">STDERR: {l.error_message}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Bottom Navigation Footer: Single-Click "Process Evidence" starts immediately without an extra confirmation step */}
            <div className="h-14 bg-white dark:bg-[#1e293b] border-t border-[#cbd5e1] dark:border-[#334155] px-6 flex items-center justify-between shrink-0 select-none">
              <div>
                {currentStep > 1 && (
                  <button
                    type="button"
                    onClick={() => setCurrentStep((prev) => Math.max(1, prev - 1))}
                    className="px-4 py-1.5 rounded bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#334155] text-slate-700 dark:text-slate-300 border border-[#cbd5e1] dark:border-[#334155] text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <ArrowLeft className="w-3.5 h-3.5" />
                    <span>Back</span>
                  </button>
                )}
              </div>

              <div className="flex items-center gap-3">
                {currentStep < 3 && (
                  <button
                    type="button"
                    onClick={() => setCurrentStep((prev) => Math.min(3, prev + 1))}
                    className="px-4 py-1.5 rounded bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#334155] text-slate-700 dark:text-slate-300 text-xs font-semibold flex items-center gap-1.5 border border-[#cbd5e1] dark:border-[#334155] transition-colors cursor-pointer"
                  >
                    <span>Configure Options</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}

                {currentStep !== 4 && (
                  <button
                    type="button"
                    id="wft-auto-start-process-btn"
                    onClick={handleStartProcessing}
                    disabled={isSubmitting || statusData?.status === 'RUNNING'}
                    className="px-5 py-2 rounded bg-[#0284c7] hover:bg-[#0369a1] disabled:opacity-50 text-white text-xs font-bold flex items-center gap-2 border border-[#0369a1] shadow-2xs transition-colors cursor-pointer"
                  >
                    <Play className="w-4 h-4 fill-current" />
                    <span>{statusData?.status === 'RUNNING' ? 'Processing...' : 'Process Evidence'}</span>
                  </button>
                )}

                {currentStep === 4 && (
                  <button
                    type="button"
                    onClick={() => {
                      if (onNavigateToExamine) onNavigateToExamine();
                    }}
                    className="px-5 py-1.5 rounded bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-semibold flex items-center gap-1.5 border border-[#0369a1] shadow-2xs transition-colors cursor-pointer"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    <span>Examine Artifacts</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      <FileBrowserModal
        isOpen={fileBrowserOpen}
        onClose={() => setFileBrowserOpen(false)}
        onSelect={handleInAppSelect}
        mode={fileBrowserMode}
        title={
          fileBrowserTarget === 'evidence'
            ? fileBrowserMode === 'file'
              ? 'Select Forensic Disk Image (.E01, .VHDX, .RAW, .ISO)'
              : 'Select Evidence Folder or Mounted Drive'
            : 'Select Target Case Storage Directory'
        }
        initialPath={fileBrowserTarget === 'evidence' ? sourcePath : targetStorageDir}
      />
    </>
  );
};