import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  Folder,
  FolderOpen,
  File,
  FileText,
  Binary,
  Search,
  RefreshCw,
  ChevronRight,
  ChevronDown,
  AlertTriangle,
  CheckCircle2,
  Bookmark,
  Copy,
  Check,
  ShieldAlert,
  Trash2,
  HardDrive,
  Database,
  ArrowRight,
  ArrowLeft,
  Disc,
  Network,
  Layers,
  Scissors,
} from 'lucide-react';
import {
  apiClient,
  FileSystemFolderItem,
  FileSystemFileItem,
  HexViewerResponse,
} from '../api/client';
import { ResizeHandle } from './ResizeHandle';
import { RowContextMenu } from './RowContextMenu';
import { GlobalFilterState } from './GlobalFilterBar';

export interface FileSystemViewProps {
  caseId: string;
  globalFilterState?: GlobalFilterState;
  initialTargetPath?: string | null;
  onClearInitialTargetPath?: () => void;
  onInspectEntity?: (entityValue: string, entityType?: string) => void;
}

interface TreeNode {
  id: string;
  label: string;
  nodeType: 'image' | 'partition' | 'volume' | 'vss' | 'carved' | 'root' | 'folder';
  folder: FileSystemFolderItem;
  children?: TreeNode[];
  isExpanded: boolean;
  isLoading: boolean;
  isLoaded: boolean;
}

function formatBytesHuman(bytes?: number | null): string {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let idx = 0;
  let val = bytes;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return `${val >= 100 || idx === 0 ? Math.round(val) : val.toFixed(1)} ${units[idx]}`;
}

function isSiBeforeFn(file: FileSystemFileItem): boolean {
  const parseUtcTsMs = (raw?: string | null): number => {
    if (!raw) return Number.NaN;
    const trimmed = raw.trim();
    if (!trimmed) return Number.NaN;
    const iso = trimmed.includes('T') ? trimmed : trimmed.replace(' ', 'T');
    const withZone = /Z$|[+-]\d{2}:?\d{2}$/i.test(iso) ? iso : `${iso}Z`;
    return Date.parse(withZone);
  };
  const checkPair = (si?: string | null, fn?: string | null) => {
    if (!si || !fn) return false;
    const siMs = parseUtcTsMs(si);
    const fnMs = parseUtcTsMs(fn);
    if (Number.isNaN(siMs) || Number.isNaN(fnMs)) return false;
    return siMs < fnMs - 1000;
  };
  return checkPair(file.si_created, file.fn_created) || checkPair(file.si_modified, file.fn_modified);
}

function extractBinaryStrings(rawBytes: Uint8Array, minLen = 4): string[] {
  const results: string[] = [];
  const seen = new Set<string>();

  // 1. Contiguous printable ASCII (0x20..0x7E)
  let asciiBuf = '';
  for (let i = 0; i < rawBytes.length; i++) {
    const b = rawBytes[i];
    if (b >= 0x20 && b <= 0x7e) {
      asciiBuf += String.fromCharCode(b);
    } else {
      if (asciiBuf.length >= minLen) {
        const trimmed = asciiBuf.trim();
        if (trimmed.length >= minLen && !seen.has(trimmed)) {
          seen.add(trimmed);
          results.push(trimmed);
        }
      }
      asciiBuf = '';
    }
  }
  if (asciiBuf.length >= minLen) {
    const trimmed = asciiBuf.trim();
    if (trimmed.length >= minLen && !seen.has(trimmed)) {
      seen.add(trimmed);
      results.push(trimmed);
    }
  }

  // 2. UTF-16LE printable strings (even byte 0x20..0x7E, odd byte 0x00)
  for (let offsetParity = 0; offsetParity <= 1; offsetParity++) {
    let u16Buf = '';
    for (let i = offsetParity; i + 1 < rawBytes.length; i += 2) {
      const lo = rawBytes[i];
      const hi = rawBytes[i + 1];
      if (hi === 0x00 && lo >= 0x20 && lo <= 0x7e) {
        u16Buf += String.fromCharCode(lo);
      } else {
        if (u16Buf.length >= minLen) {
          const trimmed = u16Buf.trim();
          if (trimmed.length >= minLen && !seen.has(trimmed)) {
            seen.add(trimmed);
            results.push(`[UTF-16LE] ${trimmed}`);
          }
        }
        u16Buf = '';
      }
    }
    if (u16Buf.length >= minLen) {
      const trimmed = u16Buf.trim();
      if (trimmed.length >= minLen && !seen.has(trimmed)) {
        seen.add(trimmed);
        results.push(`[UTF-16LE] ${trimmed}`);
      }
    }
  }

  return results;
}

export const FileSystemView: React.FC<FileSystemViewProps> = ({
  caseId,
  globalFilterState,
  initialTargetPath,
  onClearInitialTargetPath,
  onInspectEntity,
}) => {
  const [leftWidth, setLeftWidth] = useState(290);
  const [topHeightPercent, setTopHeightPercent] = useState(50);

  // FTK Imager Exact Columns: Name | Size | Type | Date Accessed | Date Created | Date Modified
  const [colWidths, setColWidths] = useState<Record<string, number>>({
    name: 260,
    size: 95,
    type: 110,
    accessed: 185,
    created: 185,
    modified: 185,
  });

  const [isDraggingLeft, setIsDraggingLeft] = useState(false);
  const [isDraggingVertical, setIsDraggingVertical] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const rightContainerRef = useRef<HTMLDivElement>(null);

  // Evidence Tree State
  const [rootNodes, setRootNodes] = useState<TreeNode[]>([]);
  const [treeSearch, setTreeSearch] = useState('');
  const [isTreeLoading, setIsTreeLoading] = useState(false);
  const [selectedFolderPath, setSelectedFolderPath] = useState<string>('.');
  const [selectedNodeLabel, setSelectedNodeLabel] = useState<string>('[root]');

  // File List State
  const [files, setFiles] = useState<FileSystemFileItem[]>([]);
  const [totalFiles, setTotalFiles] = useState(0);
  const [isFilesLoading, setIsFilesLoading] = useState(false);
  const [fileSearch, setFileSearch] = useState('');
  const [debouncedFileSearch, setDebouncedFileSearch] = useState('');
  const [isGlobalSearch, setIsGlobalSearch] = useState(false);
  const [isLoadingMoreFiles, setIsLoadingMoreFiles] = useState(false);
  const pageSize = 150;
  const [selectedFile, setSelectedFile] = useState<FileSystemFileItem | null>(null);

  // Full-Width Bottom Viewer Tabs (Hex | Text | Strings | NTFS & $MFT Properties)
  const [viewerTab, setViewerTab] = useState<'hex' | 'text' | 'strings' | 'properties'>('hex');
  const [hexData, setHexData] = useState<HexViewerResponse | null>(null);
  const [hexOffset, setHexOffset] = useState(0);
  const [hexJumpInput, setHexJumpInput] = useState('');
  const [isHexLoading, setIsHexLoading] = useState(false);
  const [hexError, setHexError] = useState<string | null>(null);
  const [textContent, setTextContent] = useState<string | null>(null);
  const [isTextLoading, setIsTextLoading] = useState(false);
  const [extractedStrings, setExtractedStrings] = useState<string[]>([]);
  const [stringsFilter, setStringsFilter] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isBookmarking, setIsBookmarking] = useState(false);
  const [bookmarkSuccess, setBookmarkSuccess] = useState(false);

  // Debounce fileSearch by 250ms
  useEffect(() => {
    const t = setTimeout(() => setDebouncedFileSearch(fileSearch.trim()), 250);
    return () => clearTimeout(t);
  }, [fileSearch]);

  // Handle "Jump to File System" target path from DetailsAndHexPane / App.tsx
  useEffect(() => {
    if (!initialTargetPath) return;
    const norm = initialTargetPath.replace(/\//g, '\\');
    const lastSep = norm.lastIndexOf('\\');
    if (lastSep > 0) {
      const parent = norm.slice(0, lastSep) || '.';
      const base = norm.slice(lastSep + 1);
      setSelectedFolderPath(parent);
      setSelectedNodeLabel(parent);
      if (base) {
        setFileSearch(base);
        setDebouncedFileSearch(base);
      }
    } else {
      setSelectedFolderPath('.');
      setSelectedNodeLabel('[Primary Evidence Volume]');
      setFileSearch(norm);
      setDebouncedFileSearch(norm);
    }
    setIsGlobalSearch(true);
    if (onClearInitialTargetPath) onClearInitialTargetPath();
  }, [initialTargetPath, onClearInitialTargetPath]);

  const [contextMenu, setContextMenu] = useState<{
    position: { x: number; y: number };
    row: Record<string, any>;
    cellValue?: unknown;
    isFolder?: boolean;
    folderPath?: string;
    filePath?: string;
  } | null>(null);

  const startColumnResize = (colKey: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const initialW = colWidths[colKey] || 140;
    const onMove = (moveEvent: MouseEvent) => {
      setColWidths((prev) => ({ ...prev, [colKey]: Math.max(70, initialW + (moveEvent.clientX - startX)) }));
    };
    const onUp = () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
    };
    document.body.style.cursor = 'col-resize';
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  };

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (isDraggingLeft && containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        setLeftWidth(Math.max(210, Math.min(e.clientX - rect.left, rect.width - 420)));
      } else if (isDraggingVertical && rightContainerRef.current) {
        const rect = rightContainerRef.current.getBoundingClientRect();
        setTopHeightPercent(Math.max(20, Math.min(((e.clientY - rect.top) / rect.height) * 100, 82)));
      }
    };
    const handleMouseUp = () => {
      setIsDraggingLeft(false);
      setIsDraggingVertical(false);
    };
    if (isDraggingLeft || isDraggingVertical) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
    }
    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, [isDraggingLeft, isDraggingVertical]);

  // Build Evidence Tree from REAL VFS partitions, VSS snapshots, Carved files, or single Primary Volume
  const loadRootTree = useCallback(async () => {
    if (!caseId) return;
    setIsTreeLoading(true);
    try {
      const [treeSettled, dashSettled] = await Promise.allSettled([
        apiClient.getFilesystemTree(caseId, ''),
        apiClient.getCaseDashboard(caseId),
      ]);

      let treeRes = treeSettled.status === 'fulfilled' ? treeSettled.value : null;
      const dashRes = dashSettled.status === 'fulfilled' ? dashSettled.value : null;

      const isLegacyMockDir = (name?: string | null) =>
        Boolean(name && name.startsWith('__PART') && name.endsWith('__'));

      let rawRootItems = (treeRes?.nodes || treeRes?.items || treeRes?.folders || []).filter(
        (f) => f && !isLegacyMockDir(f.folder_name || f.name)
      );

      if (rawRootItems.length === 0) {
        try {
          const dotTree = await apiClient.getFilesystemTree(caseId, '.');
          const dotItems = (dotTree?.nodes || dotTree?.items || dotTree?.folders || []).filter(
            (f) => f && !isLegacyMockDir(f.folder_name || f.name)
          );
          if (dotItems.length > 0) {
            rawRootItems = dotItems;
            if (!treeRes) treeRes = dotTree;
          }
        } catch {
          // ignore fallback
        }
      }

      const makeDummyFolder = (path: string, name: string): FileSystemFolderItem => ({
        folder_name: name,
        folder_path: path,
        parent_path: '',
        mft_entry_number: 5,
        sequence_number: 1,
        in_use: true,
        file_count: 0,
        is_directory: true,
      });

      const makeFolderNode = (f: FileSystemFolderItem): TreeNode => {
        const fPath = f.folder_path || f.path || f.folder_name || f.name || '.';
        const fName = f.folder_name || f.name || fPath;
        const nType = (f.node_type as TreeNode['nodeType']) || 'folder';
        return {
          id: `node_${fPath}_${fName}`,
          label: fName,
          nodeType: ['partition', 'volume', 'vss', 'carved', 'root', 'folder'].includes(nType)
            ? nType
            : 'folder',
          folder: {
            ...f,
            folder_name: fName,
            folder_path: fPath,
          },
          isExpanded: false,
          isLoading: false,
          isLoaded: false,
        };
      };

      const hasStructuredRootNodes = rawRootItems.some((i) =>
        ['partition', 'volume', 'vss', 'carved'].includes(String(i.node_type || ''))
      );

      const topChildren: TreeNode[] = [];

      if (hasStructuredRootNodes) {
        for (const item of rawRootItems) {
          topChildren.push(makeFolderNode(item));
        }
      } else {
        const partitions = treeRes?.partitions || dashRes?.partitions || [];
        const shadowCopies = treeRes?.shadow_copies || dashRes?.shadow_copies || [];
        const carvedCount =
          treeRes?.carved_files_count ??
          (treeRes?.carved_files ? treeRes.carved_files.length : undefined) ??
          dashRes?.refined_highlights?.carved_files_count ??
          0;

        if (partitions.length > 0) {
          partitions.forEach((p, idx) => {
            const pIdx = p.part_index ?? p.index ?? idx;
            const pLabel = p.label || p.desc || p.description || 'Volume';
            const pFs = p.fs_type || 'RAW';
            const pSize = p.size_bytes ?? p.length ?? 0;
            const pFolderPath = partitions.length === 1 ? '.' : `Part_${pIdx}`;
            const label = `Partition ${pIdx}: ${pLabel} [${pFs}] (${formatBytesHuman(pSize)})${
              p.is_boot ? ' [Boot]' : ''
            }`;
            topChildren.push({
              id: `part_${pIdx}`,
              label,
              nodeType: 'partition',
              folder: makeDummyFolder(pFolderPath, label),
              isExpanded: partitions.length === 1,
              isLoading: false,
              isLoaded: partitions.length === 1,
              children: partitions.length === 1 ? rawRootItems.map(makeFolderNode) : undefined,
            });
          });
        } else {
          const primaryLabel = '[Primary Evidence Volume]';
          topChildren.push({
            id: 'primary_volume',
            label: primaryLabel,
            nodeType: 'volume',
            folder: makeDummyFolder('.', primaryLabel),
            isExpanded: true,
            isLoading: false,
            isLoaded: true,
            children: rawRootItems.map(makeFolderNode),
          });
        }

        if (shadowCopies.length > 0) {
          const vssKids: TreeNode[] = shadowCopies.map((sc, idx) => {
            const vIdx = sc.vss_index ?? sc.vss_id ?? idx + 1;
            const ts = sc.creation_time || sc.timestamp_utc || sc.status || 'Snapshot';
            const count = sc.files_staged ?? sc.file_count ?? 0;
            const vPath = sc.staged_prefix || `VSS_${vIdx}`;
            const vLabel = `VSS #${vIdx} [${ts.replace('T', ' ').replace(/\.\d+$/, '')}] (${count} files)`;
            return {
              id: `vss_${vIdx}`,
              label: vLabel,
              nodeType: 'vss',
              folder: makeDummyFolder(vPath, vLabel),
              isExpanded: false,
              isLoading: false,
              isLoaded: false,
            };
          });
          topChildren.push({
            id: 'vss_container',
            label: `Volume Shadow Copies (${shadowCopies.length})`,
            nodeType: 'vss',
            folder: makeDummyFolder('staging/VSS', 'Volume Shadow Copies (VSS)'),
            isExpanded: true,
            isLoading: false,
            isLoaded: true,
            children: vssKids,
          });
        }

        if (carvedCount > 0) {
          const cLabel = `Carved Files (${carvedCount.toLocaleString()})`;
          topChildren.push({
            id: 'carved_container',
            label: cLabel,
            nodeType: 'carved',
            folder: makeDummyFolder('carved', cLabel),
            isExpanded: false,
            isLoading: false,
            isLoaded: false,
          });
        }
      }

      const rootTitle = String(
        dashRes?.case_metadata?.case_name || dashRes?.provenance?.case_id || caseId
      );
      const imageRoot: TreeNode = {
        id: 'image_root',
        label: `${rootTitle} [Evidence Source]`,
        nodeType: 'image',
        folder: makeDummyFolder('.', rootTitle),
        isExpanded: true,
        isLoading: false,
        isLoaded: true,
        children: topChildren,
      };

      setRootNodes([imageRoot]);
      if (topChildren.length > 0 && selectedNodeLabel === '[root]') {
        const partitionsOnly = topChildren.filter((n) => n.nodeType === 'partition');
        const primaryPartition =
          partitionsOnly.length > 1
            ? [...partitionsOnly].sort(
                (a, b) =>
                  Number((b.folder as any).size_bytes || 0) -
                  Number((a.folder as any).size_bytes || 0)
              )[0]
            : partitionsOnly[0];
        const initialNode = primaryPartition || topChildren[0];
        setSelectedFolderPath(initialNode.folder.folder_path || '.');
        setSelectedNodeLabel(initialNode.label);
      }
    } catch (err) {
      console.error('Failed to load Evidence Tree:', err);
    } finally {
      setIsTreeLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    loadRootTree();
  }, [loadRootTree]);

  const toggleNodeExpansion = async (nodeId: string) => {
    const updateNodes = async (nodes: TreeNode[]): Promise<TreeNode[]> => {
      const updated: TreeNode[] = [];
      for (const node of nodes) {
        if (node.id === nodeId) {
          const willExpand = !node.isExpanded;
          let children = node.children;
          if (willExpand && !node.isLoaded && node.folder.folder_path) {
            try {
              const res = await apiClient.getFilesystemTree(caseId, node.folder.folder_path);
              const subList = (res.nodes || res.items || res.folders || []).filter(
                (f) => f && !((f.folder_name || f.name || '').startsWith('__PART'))
              );
              children = subList.map((f) => {
                const fPath = f.folder_path || f.path || f.folder_name || f.name || '';
                const fName = f.folder_name || f.name || fPath;
                return {
                  id: `node_${fPath}_${fName}`,
                  label: fName,
                  nodeType: ((f.node_type as TreeNode['nodeType']) || 'folder') as TreeNode['nodeType'],
                  folder: { ...f, folder_name: fName, folder_path: fPath },
                  isExpanded: false,
                  isLoading: false,
                  isLoaded: false,
                };
              });
            } catch {
              children = [];
            }
          }
          updated.push({ ...node, isExpanded: willExpand, isLoaded: true, children });
        } else if (node.children) {
          updated.push({ ...node, children: await updateNodes(node.children) });
        } else {
          updated.push(node);
        }
      }
      return updated;
    };
    setRootNodes(await updateNodes(rootNodes));
  };

  const effectiveSearchQuery = useMemo(() => {
    const parts = [debouncedFileSearch, globalFilterState?.search?.trim() || ''].filter(Boolean);
    return parts.join(' ');
  }, [debouncedFileSearch, globalFilterState?.search]);

  const loadFiles = useCallback(
    async (reset: boolean = true) => {
      if (!caseId) return;
      if (!selectedFolderPath && !isGlobalSearch && !effectiveSearchQuery) {
        setFiles([]);
        setTotalFiles(0);
        return;
      }
      if (reset) setIsFilesLoading(true);
      else setIsLoadingMoreFiles(true);

      try {
        const res = await apiClient.getFilesystemFiles(caseId, {
          folder_path: isGlobalSearch ? '' : selectedFolderPath,
          search: effectiveSearchQuery || undefined,
          keywords:
            globalFilterState?.keywords && globalFilterState.keywords.length > 0
              ? globalFilterState.keywords
              : undefined,
          tags:
            globalFilterState?.tags && globalFilterState.tags.length > 0
              ? globalFilterState.tags
              : undefined,
          bookmarked_only: globalFilterState?.bookmarkedOnly || undefined,
          date_from: globalFilterState?.dateRange?.startUtc,
          date_to: globalFilterState?.dateRange?.endUtc,
          content_types:
            globalFilterState?.contentTypes && globalFilterState.contentTypes.length > 0
              ? globalFilterState.contentTypes
              : undefined,
          limit: pageSize,
          offset: reset ? 0 : files.length,
        });
        const list = (res.files || []).map((f) => ({
          ...f,
          file_name: f.file_name || f.name || '',
          full_path: f.full_path || f.path || f.file_name || f.name || '',
          file_size: f.file_size ?? f.size_bytes ?? 0,
          is_directory: Boolean(f.is_directory ?? f.is_dir),
          in_use: f.in_use !== undefined ? f.in_use : !f.is_deleted,
        }));
        if (reset) {
          setFiles(list);
          setSelectedFile(list.length > 0 ? list[0] : null);
        } else {
          setFiles((prev) => [...prev, ...list]);
        }
        setTotalFiles(res.total_files ?? list.length);
      } catch (err) {
        console.error('Failed to load files:', err);
      } finally {
        setIsFilesLoading(false);
        setIsLoadingMoreFiles(false);
      }
    },
    [
      caseId,
      selectedFolderPath,
      isGlobalSearch,
      effectiveSearchQuery,
      globalFilterState?.keywords,
      globalFilterState?.tags,
      globalFilterState?.bookmarkedOnly,
      globalFilterState?.dateRange?.startUtc,
      globalFilterState?.dateRange?.endUtc,
      globalFilterState?.contentTypes,
      files.length,
    ]
  );

  useEffect(() => {
    loadFiles(true);
  }, [
    caseId,
    selectedFolderPath,
    isGlobalSearch,
    effectiveSearchQuery,
    globalFilterState?.keywords,
    globalFilterState?.tags,
    globalFilterState?.bookmarkedOnly,
    globalFilterState?.dateRange?.startUtc,
    globalFilterState?.dateRange?.endUtc,
    globalFilterState?.contentTypes,
  ]);

  const displayedFiles = useMemo(() => {
    let list = files;
    const cTypes = globalFilterState?.contentTypes || [];
    if (cTypes.length > 0) {
      list = list.filter((f) => {
        if (f.is_directory) return true;
        const ext = (f.extension || f.file_name.split('.').pop() || '').toLowerCase().replace(/^\./, '');
        for (const t of cTypes) {
          if (t === 'executables' && ['exe', 'dll', 'sys', 'pf', 'ps1', 'bat', 'cmd', 'vbs'].includes(ext)) return true;
          if (t === 'documents' && ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'csv', 'lnk'].includes(ext)) return true;
          if (t === 'web' && ['html', 'htm', 'json', 'sqlite', 'db', 'cookie'].includes(ext)) return true;
          if (t === 'media' && ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'mp4', 'mov', 'avi', 'mp3', 'wav'].includes(ext)) return true;
          if (t === 'system' && ['evtx', 'dat', 'hiv', 'reg', 'log', 'ini', 'inf'].includes(ext)) return true;
        }
        return false;
      });
    }
    const startMs = globalFilterState?.dateRange?.startUtc ? Date.parse(globalFilterState.dateRange.startUtc) : NaN;
    const endMs = globalFilterState?.dateRange?.endUtc ? Date.parse(globalFilterState.dateRange.endUtc) : NaN;
    if (!Number.isNaN(startMs) || !Number.isNaN(endMs)) {
      list = list.filter((f) => {
        const tsStr = f.si_modified || f.si_created || f.si_accessed;
        if (!tsStr) return false;
        const ms = Date.parse(tsStr);
        if (Number.isNaN(ms)) return true;
        if (!Number.isNaN(startMs) && ms < startMs) return false;
        if (!Number.isNaN(endMs) && ms > endMs) return false;
        return true;
      });
    }
    return list;
  }, [files, globalFilterState?.contentTypes, globalFilterState?.dateRange?.startUtc, globalFilterState?.dateRange?.endUtc]);

  const resolveFileTargetPath = (file: FileSystemFileItem): string =>
    file.staged_file_path || file.full_path || file.path || file.file_name || file.name || '';

  const loadHexPage = useCallback(
    async (file: FileSystemFileItem, offset: number = 0) => {
      if (file.is_directory) {
        setHexData(null);
        setHexOffset(0);
        return;
      }
      const targetPath = resolveFileTargetPath(file);
      if (!targetPath) return;

      setIsHexLoading(true);
      setHexError(null);
      try {
        const hexRes = await apiClient.getHexViewer(caseId, targetPath, offset, 4096, undefined, true);
        if ((hexRes as any)?.found === false) {
          setHexData(null);
          setHexError('Raw sector bytes not staged for this file');
        } else {
          setHexData(hexRes);
          setHexOffset(offset);
        }
      } catch (err: any) {
        setHexError(err.message || 'Raw sector bytes not staged for this file');
        setHexData(null);
      } finally {
        setIsHexLoading(false);
      }
    },
    [caseId]
  );

  const loadTextAndStrings = useCallback(
    async (file: FileSystemFileItem) => {
      if (file.is_directory) {
        setTextContent(null);
        setExtractedStrings([]);
        return;
      }
      const targetPath = resolveFileTargetPath(file);
      if (!targetPath) return;

      setIsTextLoading(true);
      let loadedText: string | null = null;
      try {
        const contentRes = await apiClient.getFileContent(caseId, targetPath, 500000, undefined, true);
        loadedText = (contentRes as any)?.found === false ? null : contentRes.text_content || null;
        setTextContent(loadedText);
      } catch {
        setTextContent(null);
      } finally {
        setIsTextLoading(false);
      }

      try {
        const raw64 = await apiClient.getHexViewer(caseId, targetPath, 0, 65536, undefined, true);
        if ((raw64 as any)?.found === false) {
          setExtractedStrings([]);
          return;
        }
        const byteList: number[] = [];
        for (const line of raw64.lines || []) {
          const tokens = (line.hex_bytes || '').trim().split(/\s+/);
          for (const tok of tokens) {
            if (/^[0-9a-f]{2}$/i.test(tok)) {
              byteList.push(parseInt(tok, 16));
            }
          }
        }
        const extracted = extractBinaryStrings(new Uint8Array(byteList), 4);
        if (loadedText) {
          const extra = loadedText.match(/[A-Za-z0-9_\-./\\:@#$%^&*()+=]{4,}/g) || [];
          const set = new Set(extracted);
          for (const s of extra) {
            const t = s.trim();
            if (t.length >= 4 && !set.has(t)) {
              set.add(t);
              extracted.push(t);
            }
          }
        }
        setExtractedStrings(extracted);
      } catch {
        if (loadedText) {
          const matches = loadedText.match(/[A-Za-z0-9_\-./\\:@#$%^&*()+=]{4,}/g) || [];
          setExtractedStrings(Array.from(new Set(matches.map((s) => s.trim()))).filter((s) => s.length >= 4));
        } else {
          setExtractedStrings([]);
        }
      }
    },
    [caseId]
  );

  useEffect(() => {
    setHexOffset(0);
    setHexJumpInput('');
    setStringsFilter('');
    if (selectedFile) {
      loadHexPage(selectedFile, 0);
      loadTextAndStrings(selectedFile);
    }
  }, [selectedFile, loadHexPage, loadTextAndStrings]);

  const handleHexJump = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) return;
    const raw = hexJumpInput.trim();
    if (!raw) return;
    const parsed = raw.toLowerCase().startsWith('0x')
      ? parseInt(raw.slice(2), 16)
      : /^[0-9a-f]+$/i.test(raw) && /[a-f]/i.test(raw)
      ? parseInt(raw, 16)
      : parseInt(raw, 10);
    if (Number.isNaN(parsed) || parsed < 0) return;
    const maxOff = hexData?.file_size ? Math.max(0, hexData.file_size - 1) : parsed;
    const aligned = Math.floor(Math.min(parsed, maxOff) / 16) * 16;
    loadHexPage(selectedFile, aligned);
  };

  const filteredStrings = useMemo(() => {
    const q = stringsFilter.trim().toLowerCase();
    if (!q) return extractedStrings;
    return extractedStrings.filter((s) => s.toLowerCase().includes(q));
  }, [extractedStrings, stringsFilter]);

  const handleBookmarkFile = async () => {
    if (!selectedFile) return;
    setIsBookmarking(true);
    try {
      await apiClient.createBookmark(caseId, {
        source_table: 'raw_mft',
        source_row_id: selectedFile.mft_entry_number || 1,
        tag_name: 'Key Evidence',
        examiner_notes: `Evidence File: ${selectedFile.full_path}`,
      });
      setBookmarkSuccess(true);
      setTimeout(() => setBookmarkSuccess(false), 3000);
    } finally {
      setIsBookmarking(false);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 KB';
    if (!bytes) return '';
    return `${Math.max(1, Math.ceil(bytes / 1024)).toLocaleString()} KB`;
  };

  const formatFtkTimestamp = (ts?: string | null): string => {
    if (!ts) return '';
    return ts.replace('T', ' ').replace(/\.\d+$/, '');
  };

  const renderTreeNode = (node: TreeNode, depth: number = 0) => {
    const isSelected =
      node.folder.folder_path === selectedFolderPath && node.label === selectedNodeLabel;
    const hasKids =
      (node.children && node.children.length > 0) ||
      (!node.isLoaded && Boolean(node.folder.folder_path) && node.nodeType !== 'image');

    if (
      treeSearch.trim() &&
      node.nodeType === 'folder' &&
      !node.label.toLowerCase().includes(treeSearch.toLowerCase())
    ) {
      return null;
    }

    return (
      <div key={node.id} className="select-none">
        <div
          onClick={() => {
            setSelectedFolderPath(node.folder.folder_path);
            setSelectedNodeLabel(node.label);
            setIsGlobalSearch(false);
            setSelectedFile(null);
          }}
          onContextMenu={(e) => {
            e.preventDefault();
            e.stopPropagation();
            setContextMenu({
              position: { x: e.clientX, y: e.clientY },
              row: {
                ...node.folder,
                _row_id: node.folder.mft_entry_number ?? 5,
                file_name: node.label,
                full_path: node.folder.folder_path,
                folder_path: node.folder.folder_path,
                is_directory: true,
              },
              cellValue: node.label,
              isFolder: true,
              folderPath: node.folder.folder_path,
              filePath: node.folder.folder_path,
            });
          }}
          style={{ paddingLeft: `${depth * 14 + 4}px` }}
          className={`flex items-center gap-1 py-0.5 pr-2 text-xs cursor-pointer ${
            isSelected
              ? 'bg-[#0284c7] text-white font-semibold'
              : 'hover:bg-slate-200/70 dark:hover:bg-slate-800 text-[#0f172a] dark:text-[#f8fafc]'
          }`}
        >
          {hasKids ? (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                toggleNodeExpansion(node.id);
              }}
              className="w-3.5 h-3.5 flex items-center justify-center border border-slate-400/70 rounded-[2px] text-[10px] leading-none shrink-0"
            >
              {node.isExpanded ? '−' : '+'}
            </button>
          ) : (
            <span className="w-3.5 shrink-0" />
          )}

          {node.nodeType === 'image' ? (
            <Disc className="w-3.5 h-3.5 text-sky-500 shrink-0" />
          ) : node.nodeType === 'partition' || node.nodeType === 'volume' ? (
            <HardDrive className="w-3.5 h-3.5 text-slate-500 shrink-0" />
          ) : node.nodeType === 'vss' ? (
            <Layers className="w-3.5 h-3.5 text-indigo-500 shrink-0" />
          ) : node.nodeType === 'carved' ? (
            <Scissors className="w-3.5 h-3.5 text-rose-500 shrink-0" />
          ) : node.isExpanded ? (
            <FolderOpen className="w-3.5 h-3.5 text-amber-500 shrink-0" />
          ) : (
            <Folder className="w-3.5 h-3.5 text-amber-500 shrink-0" />
          )}

          <span className="truncate font-sans text-[12px]">{node.label}</span>
        </div>

        {node.isExpanded && node.children && node.children.length > 0 && (
          <div>{node.children.map((child) => renderTreeNode(child, depth + 1))}</div>
        )}
      </div>
    );
  };

  return (
    <div ref={containerRef} className="flex flex-col h-full w-full overflow-hidden bg-white dark:bg-[#1e293b] font-sans">
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* LEFT PANE: FTK IMAGER EVIDENCE TREE */}
        <aside
          style={{ width: `${leftWidth}px` }}
          className="flex flex-col h-full bg-white dark:bg-[#1e293b] border-r border-[#cbd5e1] dark:border-[#334155] shrink-0 overflow-hidden"
        >
          <div className="h-8 px-2.5 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0">
            <span className="text-[11px] font-bold tracking-wide text-slate-700 dark:text-slate-200">
              Evidence Tree
            </span>
            <button onClick={loadRootTree} className="p-0.5 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 cursor-pointer">
              <RefreshCw className={`w-3 h-3 ${isTreeLoading ? 'animate-spin text-[#0284c7]' : ''}`} />
            </button>
          </div>

          <div className="p-1.5 border-b border-[#e2e8f0] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a]">
            <input
              type="text"
              value={treeSearch}
              onChange={(e) => setTreeSearch(e.target.value)}
              placeholder="Filter tree folders..."
              className="w-full text-xs px-2 py-1 rounded bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] focus:outline-none focus:border-[#0284c7]"
            />
          </div>

          <div className="flex-1 overflow-auto p-1">
            {rootNodes.map((n) => renderTreeNode(n, 0))}
          </div>
        </aside>

        <ResizeHandle
          orientation="vertical"
          onMouseDown={() => setIsDraggingLeft(true)}
          isDragging={isDraggingLeft}
        />

        {/* RIGHT PANE: TOP FILE LIST + BOTTOM FULL-WIDTH VIEWER */}
        <div ref={rightContainerRef} className="flex-1 flex flex-col min-w-0 h-full overflow-hidden">
          {/* TOP-RIGHT: FTK FILE LIST */}
          <section
            style={{ height: `${topHeightPercent}%` }}
            className="flex flex-col min-h-[140px] bg-white dark:bg-[#1e293b] overflow-hidden shrink-0"
          >
            <div className="h-8 px-2.5 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between gap-2 shrink-0">
              <span className="text-[11px] font-bold text-slate-700 dark:text-slate-200">
                File List — {selectedNodeLabel}
              </span>
              <div className="flex items-center gap-1.5">
                <input
                  type="text"
                  value={fileSearch}
                  onChange={(e) => setFileSearch(e.target.value)}
                  placeholder="Filter files..."
                  className="text-xs px-2 py-0.5 rounded bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] w-48 focus:outline-none focus:border-[#0284c7]"
                />
                <button
                  type="button"
                  onClick={() => setIsGlobalSearch((p) => !p)}
                  className={`px-2 py-0.5 text-[10px] font-bold rounded border cursor-pointer ${
                    isGlobalSearch
                      ? 'bg-[#0284c7] text-white border-[#0369a1]'
                      : 'bg-white dark:bg-[#1e293b] text-slate-600 dark:text-slate-300 border-[#cbd5e1] dark:border-[#334155]'
                  }`}
                >
                  {isGlobalSearch ? 'All Partitions' : 'Active Folder'}
                </button>
              </div>
            </div>

            <div
              onScroll={(e) => {
                const t = e.currentTarget;
                if (
                  t.scrollHeight - t.scrollTop - t.clientHeight < 250 &&
                  !isFilesLoading &&
                  !isLoadingMoreFiles &&
                  files.length < totalFiles
                ) {
                  loadFiles(false);
                }
              }}
              className="flex-1 overflow-auto"
            >
              <table className="table-fixed border-collapse text-left text-xs min-w-full">
                <thead className="sticky top-0 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] z-10 text-[11px] font-semibold text-slate-700 dark:text-slate-200 select-none">
                  <tr>
                    {[
                      { key: 'name', label: 'Name', align: 'text-left' },
                      { key: 'size', label: 'Size', align: 'text-right' },
                      { key: 'type', label: 'Type', align: 'text-left' },
                      { key: 'accessed', label: 'Date Accessed', align: 'text-left' },
                      { key: 'created', label: 'Date Created', align: 'text-left' },
                      { key: 'modified', label: 'Date Modified', align: 'text-left' },
                    ].map((col) => (
                      <th
                        key={col.key}
                        style={{ width: `${colWidths[col.key]}px` }}
                        className={`relative px-2.5 py-1.5 border-r border-[#cbd5e1] dark:border-[#334155] whitespace-nowrap overflow-hidden text-ellipsis ${col.align}`}
                      >
                        <span>{col.label}</span>
                        <div
                          onMouseDown={(e) => startColumnResize(col.key, e)}
                          className="absolute top-0 right-0 w-1.5 h-full cursor-col-resize hover:bg-[#0284c7]/60"
                        />
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="font-sans text-[12px]">
                  {displayedFiles.length === 0 && !isFilesLoading ? (
                    <tr>
                      <td colSpan={6} className="py-10 text-center text-slate-400 text-xs">
                        No files in this directory or matching active filters.
                      </td>
                    </tr>
                  ) : (
                    displayedFiles.map((file, idx) => {
                      const isSelected = selectedFile?.full_path === file.full_path;
                      const resolvedRowPath = resolveFileTargetPath(file);
                      return (
                        <tr
                          key={`${file.full_path}_${idx}`}
                          onClick={() => setSelectedFile(file)}
                          onDoubleClick={() => {
                            if (file.is_directory) {
                              setSelectedFolderPath(file.full_path);
                              setSelectedNodeLabel(file.file_name);
                              setIsGlobalSearch(false);
                            }
                          }}
                          onContextMenu={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            setSelectedFile(file);
                            setContextMenu({
                              position: { x: e.clientX, y: e.clientY },
                              row: {
                                ...file,
                                _row_id: file.mft_entry ?? file.mft_entry_number ?? idx + 1,
                                file_path: resolvedRowPath,
                                full_path: file.full_path,
                                folder_path: file.is_directory ? file.full_path : file.parent_path,
                              },
                              cellValue: file.file_name,
                              isFolder: file.is_directory,
                              folderPath: file.is_directory ? file.full_path : undefined,
                              filePath: resolvedRowPath,
                            });
                          }}
                          className={`cursor-pointer border-b border-[#e2e8f0] dark:border-[#334155] ${
                            isSelected
                              ? 'bg-[#0284c7] text-white'
                              : 'hover:bg-sky-50 dark:hover:bg-slate-800/70 text-[#0f172a] dark:text-[#f8fafc]'
                          }`}
                        >
                          <td className="px-2.5 py-1 border-r border-[#e2e8f0] dark:border-[#334155] overflow-hidden">
                            <div className="flex items-center gap-1.5 min-w-0">
                              {file.is_directory ? (
                                <Folder className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                              ) : !file.in_use ? (
                                <Trash2 className="w-3.5 h-3.5 text-rose-500 shrink-0" />
                              ) : (
                                <File className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                              )}
                              <span className={`truncate ${!file.in_use ? 'line-through' : ''}`}>
                                {file.file_name}
                              </span>
                            </div>
                          </td>
                          <td className="px-2.5 py-1 border-r border-[#e2e8f0] dark:border-[#334155] text-right whitespace-nowrap font-mono text-[11px]">
                            {file.is_directory ? '' : formatFileSize(file.file_size)}
                          </td>
                          <td className="px-2.5 py-1 border-r border-[#e2e8f0] dark:border-[#334155] whitespace-nowrap text-[11px]">
                            {file.is_directory ? 'File folder' : file.extension ? `${file.extension.toUpperCase()} File` : 'File'}
                          </td>
                          <td className="px-2.5 py-1 border-r border-[#e2e8f0] dark:border-[#334155] whitespace-nowrap font-mono text-[11px]">
                            {formatFtkTimestamp(file.si_accessed)}
                          </td>
                          <td className="px-2.5 py-1 border-r border-[#e2e8f0] dark:border-[#334155] whitespace-nowrap font-mono text-[11px]">
                            {formatFtkTimestamp(file.si_created)}
                          </td>
                          <td className="px-2.5 py-1 whitespace-nowrap font-mono text-[11px]">
                            {formatFtkTimestamp(file.si_modified)}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <ResizeHandle
            orientation="horizontal"
            onMouseDown={() => setIsDraggingVertical(true)}
            isDragging={isDraggingVertical}
          />

          {/* BOTTOM-RIGHT: FULL-WIDTH FTK HEX / TEXT / NTFS PROPERTIES VIEWER */}
          <section className="flex-1 flex flex-col min-h-[140px] bg-white dark:bg-[#1e293b] overflow-hidden">
            <div className="h-8 px-2.5 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0">
              <div className="flex items-center gap-1">
                {[
                  { id: 'hex', label: 'Hex Viewer', icon: Binary },
                  { id: 'text', label: 'Text / ASCII', icon: FileText },
                  { id: 'strings', label: 'Strings', icon: Search },
                  { id: 'properties', label: 'NTFS & $MFT Properties', icon: Database },
                ].map((t) => {
                  const Icon = t.icon;
                  return (
                    <button
                      key={t.id}
                      type="button"
                      onClick={() => setViewerTab(t.id as any)}
                      className={`flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-semibold rounded cursor-pointer ${
                        viewerTab === t.id
                          ? 'bg-[#0284c7] text-white'
                          : 'text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-800'
                      }`}
                    >
                      <Icon className="w-3 h-3" />
                      <span>{t.label}</span>
                    </button>
                  );
                })}
              </div>

              {selectedFile && (
                <button
                  type="button"
                  onClick={handleBookmarkFile}
                  disabled={isBookmarking}
                  className="px-2 py-0.5 text-[11px] font-semibold rounded bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] hover:bg-slate-100 dark:hover:bg-[#334155] flex items-center gap-1 cursor-pointer"
                >
                  <Bookmark className="w-3 h-3 text-amber-500" />
                  <span>{bookmarkSuccess ? 'Bookmarked!' : 'Bookmark'}</span>
                </button>
              )}
            </div>

            <div className="flex-1 overflow-auto p-3 font-mono text-xs">
              {!selectedFile ? (
                <div className="flex items-center justify-center h-full text-slate-400 font-sans text-xs">
                  Select an item in the File List to inspect Hex bytes, Text, Strings, or NTFS $MFT attributes.
                </div>
              ) : viewerTab === 'properties' ? (
                (() => {
                  const mftEntry = selectedFile.mft_entry ?? selectedFile.mft_entry_number;
                  const isDeleted = selectedFile.is_deleted ?? selectedFile.in_use === false;
                  const siChanged = selectedFile.si_changed ?? selectedFile.si_mft_modified;
                  const isTimestomped = Boolean(selectedFile.timestomped) || isSiBeforeFn(selectedFile);
                  const cleanPath = selectedFile.full_path || selectedFile.path || selectedFile.file_name;

                  return (
                    <div className="space-y-3 font-sans text-xs max-w-5xl">
                      <div className="grid grid-cols-4 gap-3">
                        <div className="p-2.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a]">
                          <span className="text-[10px] text-slate-400 font-bold uppercase block">MFT Entry #</span>
                          <span className="font-mono font-bold text-[#0284c7]">{mftEntry ?? 'N/A'}</span>
                        </div>
                        <div className="p-2.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a]">
                          <span className="text-[10px] text-slate-400 font-bold uppercase block">Sequence #</span>
                          <span className="font-mono font-bold">{selectedFile.sequence_number ?? 'N/A'}</span>
                        </div>
                        <div className="p-2.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a]">
                          <span className="text-[10px] text-slate-400 font-bold uppercase block">Allocation Status</span>
                          <span className={`font-bold ${!isDeleted ? 'text-emerald-600' : 'text-rose-600'}`}>
                            {!isDeleted ? 'ALLOCATED' : 'DELETED'}
                          </span>
                        </div>
                        <div className="p-2.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a] flex flex-col justify-center">
                          <span className="text-[10px] text-slate-400 font-bold uppercase block">Clock Integrity</span>
                          {isTimestomped ? (
                            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-rose-100 dark:bg-rose-950/70 text-rose-700 dark:text-rose-300 border border-rose-300 dark:border-rose-800 font-bold text-[10px] w-fit">
                              <AlertTriangle className="w-3 h-3 shrink-0" />
                              <span>TIMESTOMPED ($SI &lt; $FN)</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-emerald-600 font-semibold text-[11px]">
                              <CheckCircle2 className="w-3 h-3 shrink-0" />
                              <span>Consistent ($SI / $FN)</span>
                            </span>
                          )}
                        </div>
                      </div>

                      {/* 8-Timestamp $STANDARD_INFORMATION (0x10) vs $FILE_NAME (0x30) MACB Table */}
                      <div className="rounded border border-[#cbd5e1] dark:border-[#334155] overflow-hidden">
                        <table className="w-full text-left border-collapse text-xs">
                          <thead className="bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] text-[10.5px] uppercase text-slate-600 dark:text-slate-300">
                            <tr>
                              <th className="px-3 py-1.5 font-bold w-40">MACB Attribute</th>
                              <th className="px-3 py-1.5 font-bold">$STANDARD_INFORMATION (0x10)</th>
                              <th className="px-3 py-1.5 font-bold">$FILE_NAME (0x30)</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-[#e2e8f0] dark:divide-[#334155] font-mono text-[11px]">
                            <tr>
                              <td className="px-3 py-1.5 font-sans font-semibold text-amber-700 dark:text-amber-400">M — Modified</td>
                              <td className="px-3 py-1.5">{formatFtkTimestamp(selectedFile.si_modified) || '—'}</td>
                              <td className="px-3 py-1.5">{formatFtkTimestamp(selectedFile.fn_modified) || '—'}</td>
                            </tr>
                            <tr>
                              <td className="px-3 py-1.5 font-sans font-semibold text-sky-700 dark:text-sky-400">A — Accessed</td>
                              <td className="px-3 py-1.5">{formatFtkTimestamp(selectedFile.si_accessed) || '—'}</td>
                              <td className="px-3 py-1.5">{formatFtkTimestamp(selectedFile.fn_accessed) || '—'}</td>
                            </tr>
                            <tr>
                              <td className="px-3 py-1.5 font-sans font-semibold text-purple-700 dark:text-purple-400">C — MFT Entry Changed</td>
                              <td className="px-3 py-1.5">{formatFtkTimestamp(siChanged) || '—'}</td>
                              <td className="px-3 py-1.5">{formatFtkTimestamp(selectedFile.fn_changed) || '—'}</td>
                            </tr>
                            <tr>
                              <td className="px-3 py-1.5 font-sans font-semibold text-emerald-700 dark:text-emerald-400">B — Born / Created</td>
                              <td className="px-3 py-1.5">{formatFtkTimestamp(selectedFile.si_created) || '—'}</td>
                              <td className="px-3 py-1.5">{formatFtkTimestamp(selectedFile.fn_created) || '—'}</td>
                            </tr>
                          </tbody>
                        </table>
                      </div>

                      <div className="p-2.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a] flex items-center justify-between gap-2">
                        <div className="min-w-0">
                          <span className="text-[10px] font-sans text-slate-400 font-bold uppercase block">
                            Full Evidence Path
                          </span>
                          <span className="font-mono text-[11px] break-all">{cleanPath}</span>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <button
                            type="button"
                            onClick={() => {
                              navigator.clipboard.writeText(cleanPath);
                              setCopiedKey('fs_path');
                              setTimeout(() => setCopiedKey(null), 1500);
                            }}
                            className="px-2 py-1 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] hover:bg-slate-50 dark:hover:bg-[#334155] text-[11px] font-semibold flex items-center gap-1 cursor-pointer"
                          >
                            {copiedKey === 'fs_path' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedKey === 'fs_path' ? 'Copied' : 'Copy'}</span>
                          </button>
                          {onInspectEntity && selectedFile.file_name && (
                            <button
                              type="button"
                              onClick={() => onInspectEntity(selectedFile.file_name, 'file')}
                              className="px-2.5 py-1 rounded bg-[#0284c7] hover:bg-[#0369a1] text-white text-[11px] font-semibold flex items-center gap-1 cursor-pointer"
                            >
                              <Network className="w-3 h-3" />
                              <span>Inspect in Graph</span>
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })()
              ) : viewerTab === 'hex' ? (
                hexData && hexData.lines.length > 0 ? (
                  <div className="flex flex-col gap-2">
                    <div className="sticky top-0 z-10 bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded px-2.5 py-1.5 flex flex-wrap items-center justify-between gap-2 font-sans text-[11px]">
                      <span className="font-mono text-slate-600 dark:text-slate-300">
                        Offset <strong>0x{hexOffset.toString(16).padStart(8, '0').toUpperCase()}</strong> —{' '}
                        {Math.min(hexOffset + 4096, hexData.file_size).toLocaleString()} / {hexData.file_size.toLocaleString()} B ({hexData.lines.length} rows)
                      </span>
                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          disabled={hexOffset === 0 || isHexLoading}
                          onClick={() => loadHexPage(selectedFile, Math.max(0, hexOffset - 4096))}
                          className="px-2 py-0.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] disabled:opacity-40 flex items-center gap-1 cursor-pointer font-semibold"
                        >
                          <ArrowLeft className="w-3 h-3" />
                          <span>Prev 4KB</span>
                        </button>
                        <button
                          type="button"
                          disabled={hexOffset + 4096 >= hexData.file_size || isHexLoading}
                          onClick={() => loadHexPage(selectedFile, hexOffset + 4096)}
                          className="px-2 py-0.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] disabled:opacity-40 flex items-center gap-1 cursor-pointer font-semibold"
                        >
                          <span>Next 4KB</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                        <form onSubmit={handleHexJump} className="flex items-center gap-1 ml-1">
                          <input
                            type="text"
                            value={hexJumpInput}
                            onChange={(e) => setHexJumpInput(e.target.value)}
                            placeholder="Jump (e.g. 0x0040)"
                            className="w-32 px-2 py-0.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] font-mono text-[11px] focus:outline-none focus:border-[#0284c7]"
                          />
                          <button
                            type="submit"
                            className="px-2 py-0.5 rounded bg-[#0284c7] hover:bg-[#0369a1] text-white font-semibold cursor-pointer"
                          >
                            Go
                          </button>
                        </form>
                      </div>
                    </div>

                    <div className="space-y-0.5 select-text">
                      {hexData.lines.map((line) => (
                        <div key={line.offset} className="flex items-center leading-relaxed hover:bg-sky-50 dark:hover:bg-sky-950/30 px-1">
                          <span className="w-24 text-slate-400 font-bold shrink-0">{line.offset_hex}</span>
                          <span className="w-[420px] text-[#0f172a] dark:text-[#f8fafc] shrink-0 tracking-wider">{line.hex_bytes}</span>
                          <span className="text-emerald-700 dark:text-emerald-400 whitespace-pre pl-4 border-l border-[#cbd5e1] dark:border-[#334155]">
                            {line.ascii_repr}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="text-slate-400 font-sans text-xs py-6 text-center">
                    {selectedFile.is_directory
                      ? `Folder "${selectedFile.file_name}" — double-click in the File List to open, or switch to the "NTFS & $MFT Properties" tab.`
                      : isHexLoading
                      ? 'Loading raw sector bytes...'
                      : hexError || 'No binary stream available for this entry.'}
                  </div>
                )
              ) : viewerTab === 'text' ? (
                <pre className="whitespace-pre-wrap text-xs">
                  {isTextLoading ? 'Loading UTF-8 / ASCII text...' : textContent || 'No readable UTF-8 text in this file.'}
                </pre>
              ) : (
                <div className="flex flex-col gap-2">
                  <div className="sticky top-0 z-10 bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded px-2.5 py-1.5 flex items-center justify-between gap-2 font-sans text-xs">
                    <div className="relative flex-1 max-w-md">
                      <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2 pointer-events-none" />
                      <input
                        type="text"
                        value={stringsFilter}
                        onChange={(e) => setStringsFilter(e.target.value)}
                        placeholder="Filter extracted ASCII / UTF-16LE strings..."
                        className="w-full pl-8 pr-2 py-1 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] text-xs focus:outline-none focus:border-[#0284c7]"
                      />
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] font-mono text-[11px] font-semibold">
                        {filteredStrings.length.toLocaleString()} / {extractedStrings.length.toLocaleString()} strings
                      </span>
                      <button
                        type="button"
                        disabled={filteredStrings.length === 0}
                        onClick={() => {
                          navigator.clipboard.writeText(filteredStrings.join('\n'));
                          setCopiedKey('strings_all');
                          setTimeout(() => setCopiedKey(null), 1500);
                        }}
                        className="px-2 py-0.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] hover:bg-slate-50 dark:hover:bg-[#334155] disabled:opacity-40 text-[11px] font-semibold flex items-center gap-1 cursor-pointer"
                      >
                        {copiedKey === 'strings_all' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedKey === 'strings_all' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  </div>
                  <div className="space-y-1 text-[11px] select-text">
                    {filteredStrings.length === 0 ? (
                      <div className="text-slate-400 font-sans text-xs py-4 text-center">
                        No printable ASCII / UTF-16LE strings match the current filter.
                      </div>
                    ) : (
                      filteredStrings.map((s, i) => <div key={i}>{s}</div>)
                    )}
                  </div>
                </div>
              )}
            </div>
          </section>
        </div>
      </div>

      {/* BOTTOM STATUS BAR */}
      <div className="h-6 px-3 bg-[#f1f5f9] dark:bg-[#0f172a] border-t border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between text-[11px] font-mono text-slate-600 dark:text-slate-300 shrink-0">
        <span>
          Listed: {displayedFiles.length.toLocaleString()} / {totalFiles.toLocaleString()} | Selected:{' '}
          {selectedFile ? selectedFile.file_name : 'None'}
        </span>
        <span className="truncate max-w-[55%]">
          {caseId} :: {selectedNodeLabel} ({selectedFolderPath || '.'})
        </span>
      </div>

      {contextMenu && (
        <RowContextMenu
          caseId={caseId}
          position={contextMenu.position}
          onClose={() => setContextMenu(null)}
          row={contextMenu.row}
          tableName="raw_mft"
          isFolder={contextMenu.isFolder}
          folderPath={contextMenu.folderPath}
          filePath={contextMenu.filePath}
          cellValue={contextMenu.cellValue}
          onInspectEntity={onInspectEntity ? (ev) => onInspectEntity(ev) : undefined}
        />
      )}
    </div>
  );
};