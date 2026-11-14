import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  Folder,
  FolderOpen,
  File,
  FileCode,
  FileText,
  Binary,
  Search,
  RefreshCw,
  ChevronRight,
  ChevronDown,
  ChevronLeft,
  AlertTriangle,
  CheckCircle2,
  Bookmark,
  Copy,
  Check,
  ExternalLink,
  ShieldAlert,
  Trash2,
  HardDrive,
  Clock,
  Database,
  ArrowRight,
  ArrowLeft,
  Sliders,
  Eye,
  Layers,
  Sparkles,
} from 'lucide-react';
import {
  apiClient,
  FileSystemFolderItem,
  FileSystemFileItem,
  HexViewerResponse,
  FileContentResponse,
} from '../api/client';
import { ResizeHandle } from './ResizeHandle';
import { RowContextMenu } from './RowContextMenu';

interface FileSystemViewProps {
  caseId: string;
}

interface TreeNode {
  folder: FileSystemFolderItem;
  children?: TreeNode[];
  isExpanded: boolean;
  isLoading: boolean;
  isLoaded: boolean;
}

export const FileSystemView: React.FC<FileSystemViewProps> = ({ caseId }) => {
  // ---------------------------------------------------------------------------
  // Pane Layout & Draggable Resizing State (Persisted in localStorage)
  // ---------------------------------------------------------------------------
  const [leftWidth, setLeftWidth] = useState(() => {
    try {
      const stored = localStorage.getItem('wft_filesystem_left_width');
      if (stored) {
        const val = Number(stored);
        if (!isNaN(val) && val >= 180 && val <= 650) return val;
      }
    } catch {}
    return 280;
  });
  const [topHeightPercent, setTopHeightPercent] = useState(() => {
    try {
      const stored = localStorage.getItem('wft_filesystem_top_percent');
      if (stored) {
        const val = Number(stored);
        if (!isNaN(val) && val >= 15 && val <= 85) return val;
      }
    } catch {}
    return 52;
  });
  const [bottomLeftPercent, setBottomLeftPercent] = useState(() => {
    try {
      const stored = localStorage.getItem('wft_filesystem_bottom_left_percent');
      if (stored) {
        const val = Number(stored);
        if (!isNaN(val) && val >= 20 && val <= 80) return val;
      }
    } catch {}
    return 55;
  });

  const [isDraggingLeft, setIsDraggingLeft] = useState(false);
  const [isDraggingVertical, setIsDraggingVertical] = useState(false);
  const [isDraggingBottom, setIsDraggingBottom] = useState(false);

  const containerRef = useRef<HTMLDivElement>(null);
  const rightContainerRef = useRef<HTMLDivElement>(null);
  const bottomContainerRef = useRef<HTMLDivElement>(null);

  // ---------------------------------------------------------------------------
  // Directory Tree State
  // ---------------------------------------------------------------------------
  const [rootNodes, setRootNodes] = useState<TreeNode[]>([]);
  const [treeSearch, setTreeSearch] = useState('');
  const [isTreeLoading, setIsTreeLoading] = useState(false);
  const [selectedFolderPath, setSelectedFolderPath] = useState<string>('.');

  // ---------------------------------------------------------------------------
  // File List Table State
  // ---------------------------------------------------------------------------
  const [files, setFiles] = useState<FileSystemFileItem[]>([]);
  const [totalFiles, setTotalFiles] = useState(0);
  const [isFilesLoading, setIsFilesLoading] = useState(false);
  const [fileSearch, setFileSearch] = useState('');
  const [isGlobalSearch, setIsGlobalSearch] = useState(false);
  const [isLoadingMoreFiles, setIsLoadingMoreFiles] = useState(false);
  const pageSize = 150;
  const [selectedFile, setSelectedFile] = useState<FileSystemFileItem | null>(null);

  // ---------------------------------------------------------------------------
  // Bottom Left: Hex / Text / Strings Viewer State
  // ---------------------------------------------------------------------------
  const [viewerTab, setViewerTab] = useState<'hex' | 'text' | 'strings'>('hex');
  const [hexData, setHexData] = useState<HexViewerResponse | null>(null);
  const [hexOffset, setHexOffset] = useState(0);
  const [isHexLoading, setIsHexLoading] = useState(false);
  const [hexError, setHexError] = useState<string | null>(null);

  const [textContent, setTextContent] = useState<string | null>(null);
  const [isTextLoading, setIsTextLoading] = useState(false);

  const [extractedStrings, setExtractedStrings] = useState<string[]>([]);
  const [stringsFilter, setStringsFilter] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // ---------------------------------------------------------------------------
  // Bottom Right: Bookmark State
  // ---------------------------------------------------------------------------
  const [isBookmarking, setIsBookmarking] = useState(false);
  const [bookmarkSuccess, setBookmarkSuccess] = useState(false);

  // Right-Click Context Menu State
  const [contextMenu, setContextMenu] = useState<{
    position: { x: number; y: number };
    row: Record<string, any>;
    cellValue?: unknown;
    isFolder?: boolean;
    folderPath?: string;
    filePath?: string;
  } | null>(null);

  // ---------------------------------------------------------------------------
  // Resize Splitter Event Handlers
  // ---------------------------------------------------------------------------
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (isDraggingLeft && containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        const newWidth = Math.max(180, Math.min(e.clientX - rect.left, rect.width - 400));
        setLeftWidth(newWidth);
        try {
          localStorage.setItem('wft_filesystem_left_width', String(newWidth));
        } catch {}
      } else if (isDraggingVertical && rightContainerRef.current) {
        const rect = rightContainerRef.current.getBoundingClientRect();
        const offsetY = e.clientY - rect.top;
        const newPercent = Math.max(15, Math.min((offsetY / rect.height) * 100, 85));
        setTopHeightPercent(newPercent);
        try {
          localStorage.setItem('wft_filesystem_top_percent', String(newPercent));
        } catch {}
      } else if (isDraggingBottom && bottomContainerRef.current) {
        const rect = bottomContainerRef.current.getBoundingClientRect();
        const offsetX = e.clientX - rect.left;
        const newPercent = Math.max(20, Math.min((offsetX / rect.width) * 100, 80));
        setBottomLeftPercent(newPercent);
        try {
          localStorage.setItem('wft_filesystem_bottom_left_percent', String(newPercent));
        } catch {}
      }
    };

    const handleMouseUp = () => {
      setIsDraggingLeft(false);
      setIsDraggingVertical(false);
      setIsDraggingBottom(false);
    };

    if (isDraggingLeft || isDraggingVertical || isDraggingBottom) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
      document.body.style.userSelect = 'none';
      if (isDraggingLeft || isDraggingBottom) {
        document.body.style.cursor = 'col-resize';
      } else {
        document.body.style.cursor = 'row-resize';
      }
    } else {
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }

    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, [isDraggingLeft, isDraggingVertical, isDraggingBottom]);

  // ---------------------------------------------------------------------------
  // Load Directory Tree (Root & Expansion)
  // ---------------------------------------------------------------------------
  const loadRootTree = useCallback(async () => {
    if (!caseId) return;
    setIsTreeLoading(true);
    try {
      const res = await apiClient.getFilesystemTree(caseId, '');
      const rootFolders = res.folders || [];

      // Create a virtual root node wrapping the top-level items
      const virtualRoot: TreeNode = {
        folder: {
          folder_name: 'Root (C:\\)',
          folder_path: '.',
          parent_path: '',
          mft_entry_number: 5,
          sequence_number: 5,
          in_use: true,
          file_count: res.total_folders,
          is_directory: true,
        },
        children: rootFolders.map((f) => ({
          folder: f,
          isExpanded: false,
          isLoading: false,
          isLoaded: false,
        })),
        isExpanded: true,
        isLoading: false,
        isLoaded: true,
      };

      setRootNodes([virtualRoot]);
    } catch (err) {
      console.error('Failed to load root filesystem tree:', err);
    } finally {
      setIsTreeLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    loadRootTree();
  }, [loadRootTree]);

  // Recursively toggle and load tree children
  const toggleNodeExpansion = async (nodePath: string) => {
    const updateNodes = async (nodes: TreeNode[]): Promise<TreeNode[]> => {
      const updated: TreeNode[] = [];
      for (const node of nodes) {
        if (node.folder.folder_path === nodePath) {
          const willExpand = !node.isExpanded;
          let children = node.children;

          if (willExpand && !node.isLoaded) {
            try {
              node.isLoading = true;
              const res = await apiClient.getFilesystemTree(caseId, node.folder.folder_path);
              children = (res.folders || []).map((f) => ({
                folder: f,
                isExpanded: false,
                isLoading: false,
                isLoaded: false,
              }));
            } catch (err) {
              console.error(`Failed to load subfolders for ${node.folder.folder_path}:`, err);
            } finally {
              node.isLoading = false;
            }
          }

          updated.push({
            ...node,
            isExpanded: willExpand,
            isLoaded: true,
            children,
          });
        } else if (node.children && node.children.length > 0) {
          updated.push({
            ...node,
            children: await updateNodes(node.children),
          });
        } else {
          updated.push(node);
        }
      }
      return updated;
    };

    const newRoots = await updateNodes(rootNodes);
    setRootNodes(newRoots);
  };

  // ---------------------------------------------------------------------------
  // Load Files for Selected Folder
  // ---------------------------------------------------------------------------
  const loadFiles = useCallback(async (reset: boolean = true) => {
    if (!caseId) return;
    if (reset) {
      setIsFilesLoading(true);
    } else {
      setIsLoadingMoreFiles(true);
    }
    try {
      const folderParam = isGlobalSearch ? '' : selectedFolderPath;
      const offset = reset ? 0 : files.length;
      const res = await apiClient.getFilesystemFiles(caseId, {
        folder_path: folderParam,
        search: fileSearch.trim() || undefined,
        limit: pageSize,
        offset,
      });

      if (reset) {
        setFiles(res.files || []);
        if (res.files && res.files.length > 0) {
          setSelectedFile(res.files[0]);
        } else {
          setSelectedFile(null);
        }
      } else {
        setFiles((prev) => [...prev, ...(res.files || [])]);
      }
      setTotalFiles(res.total_files || 0);
    } catch (err) {
      console.error('Failed to load filesystem files:', err);
    } finally {
      setIsFilesLoading(false);
      setIsLoadingMoreFiles(false);
    }
  }, [caseId, selectedFolderPath, isGlobalSearch, fileSearch, files.length]);

  useEffect(() => {
    loadFiles(true);
  }, [caseId, selectedFolderPath, isGlobalSearch, fileSearch]);

  const handleSelectFolder = (folderPath: string) => {
    setSelectedFolderPath(folderPath);
    setIsGlobalSearch(false);
    setSelectedFile(null);
  };

  // ---------------------------------------------------------------------------
  // File Selection & Hex/Text/Strings Preview
  // ---------------------------------------------------------------------------
  const loadFilePreviews = useCallback(
    async (file: FileSystemFileItem, offset: number = 0) => {
      // If the selected item is a directory, directories do not have raw hex data streams
      if (file.is_directory) {
        setIsHexLoading(false);
        setIsTextLoading(false);
        setHexError(null);
        setHexData(null);
        setTextContent(null);
        setExtractedStrings([]);
        return;
      }

      const targetPath = file.staged_file_path || file.full_path || file.file_name;
      if (!targetPath) return;

      setIsHexLoading(true);
      setHexError(null);
      setIsTextLoading(true);

      // 1. Fetch Hex Chunk
      try {
        const hexRes = await apiClient.getHexViewer(caseId, targetPath, offset, 4096);
        setHexData(hexRes);
        setHexOffset(offset);

        // Extract printable strings from ASCII bytes representation
        const asciiChunk = (hexRes.lines || []).map((l) => l.ascii_repr).join('');
        const rawMatches: string[] = asciiChunk.match(/[A-Za-z0-9_\-\.\/\\: @#$%^&*()+=]{4,}/g) || [];
        const uniqueStrings: string[] = Array.from(new Set(rawMatches.map((s) => s.trim()))).filter(
          (s) => s.length >= 4 && !/^\.+$/.test(s)
        );
        setExtractedStrings(uniqueStrings);
      } catch (err: any) {
        setHexError(err.message || 'Evidence file bytes not accessible');
        setHexData(null);
        setExtractedStrings([]);
      } finally {
        setIsHexLoading(false);
      }

      // 2. Fetch Text Preview Content
      try {
        const contentRes = await apiClient.getFileContent(caseId, targetPath, 500000);
        if (contentRes.text_content) {
          setTextContent(contentRes.text_content);
          // If we got full text, extract more comprehensive strings
          const fullMatches: string[] = contentRes.text_content.match(/[A-Za-z0-9_\-\.\/\\: @#$%^&*()+=]{4,}/g) || [];
          const combined: string[] = Array.from(new Set(fullMatches.map((s) => s.trim()))).filter(
            (s) => s.length >= 4 && !/^\.+$/.test(s)
          );
          if (combined.length > 0) {
            setExtractedStrings(combined);
          }
        } else {
          setTextContent(null);
        }
      } catch {
        setTextContent(null);
      } finally {
        setIsTextLoading(false);
      }
    },
    [caseId]
  );

  useEffect(() => {
    if (selectedFile) {
      loadFilePreviews(selectedFile, 0);
    } else {
      setHexData(null);
      setTextContent(null);
      setExtractedStrings([]);
    }
  }, [selectedFile, loadFilePreviews]);

  // ---------------------------------------------------------------------------
  // Bookmark Action
  // ---------------------------------------------------------------------------
  const handleBookmarkFile = async () => {
    if (!selectedFile) return;
    setIsBookmarking(true);
    try {
      await apiClient.createBookmark(caseId, {
        source_table: 'raw_mft',
        source_row_id: selectedFile.mft_entry_number || 1,
        tag_name: 'Key Evidence',
        examiner_notes: `Evidence File: ${selectedFile.full_path} (Size: ${formatFileSize(
          selectedFile.file_size
        )}, MFT Entry: ${selectedFile.mft_entry_number ?? 'N/A'})`,
      });
      setBookmarkSuccess(true);
      setTimeout(() => setBookmarkSuccess(false), 3000);
    } catch (err) {
      console.error('Failed to create bookmark:', err);
    } finally {
      setIsBookmarking(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Timestomping Discrepancy Detection Logic
  // ---------------------------------------------------------------------------
  const timestompAnalysis = useMemo(() => {
    if (!selectedFile) return null;
    const siCreatedStr = selectedFile.si_created;
    const fnCreatedStr = selectedFile.fn_created;
    const siModifiedStr = selectedFile.si_modified;

    if (!siCreatedStr || !fnCreatedStr) return null;

    const siCreated = new Date(siCreatedStr).getTime();
    const fnCreated = new Date(fnCreatedStr).getTime();
    const siModified = siModifiedStr ? new Date(siModifiedStr).getTime() : null;

    // In NTFS, timestomping occurs when $SI Created is artificially rolled back to predate $FN Created.
    // ($SI Modified predating $FN Created is standard Windows file copy behavior and not timestomping).
    const hasTimestomp =
      !isNaN(siCreated) &&
      !isNaN(fnCreated) &&
      siCreated < fnCreated - 5000;

    let diffText = '';
    if (hasTimestomp && !isNaN(siCreated) && !isNaN(fnCreated)) {
      const diffMs = fnCreated - siCreated;
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      const diffHours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      diffText = `${diffDays} days, ${diffHours} hours`;
    }

    return {
      hasTimestomp,
      diffText,
      siCreatedStr,
      fnCreatedStr,
    };
  }, [selectedFile]);

  // ---------------------------------------------------------------------------
  // Helper: Format Bytes Human-Readable
  // ---------------------------------------------------------------------------
  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    if (!bytes) return '-';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // ---------------------------------------------------------------------------
  // Render Recursive Directory Tree Node
  // ---------------------------------------------------------------------------
  const renderTreeNode = (node: TreeNode, depth: number = 0) => {
    const isSelected = selectedFolderPath === node.folder.folder_path;
    const hasChildren = (node.children && node.children.length > 0) || !node.isLoaded;

    return (
      <div key={node.folder.folder_path} className="select-none">
        <div
          onClick={() => handleSelectFolder(node.folder.folder_path)}
          onContextMenu={(e) => {
            e.preventDefault();
            handleSelectFolder(node.folder.folder_path);
            setContextMenu({
              position: { x: e.clientX, y: e.clientY },
              row: {
                file_name: node.folder.folder_name,
                file_path: node.folder.folder_path,
                is_directory: true,
                _table_name: 'raw_mft',
                _row_id: node.folder.mft_entry_number,
              },
              isFolder: true,
              folderPath: node.folder.folder_path,
              cellValue: node.folder.folder_name,
            });
          }}
          style={{ paddingLeft: `${depth * 14 + 6}px` }}
          className={`flex items-center justify-between py-1 pr-2 rounded text-xs transition-colors cursor-pointer group ${
            isSelected
              ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0369a1] dark:text-[#38bdf8] font-bold border-l-3 border-l-[#0284c7]'
              : 'hover:bg-slate-100 dark:hover:bg-[#1e293b] text-[#0f172a] dark:text-[#f8fafc]'
          }`}
          title={node.folder.folder_path}
        >
          <div className="flex items-center gap-1.5 min-w-0 pr-1">
            {hasChildren ? (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  toggleNodeExpansion(node.folder.folder_path);
                }}
                className="p-0.5 rounded text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
              >
                {node.isLoading ? (
                  <RefreshCw className="w-3 h-3 animate-spin text-[#0284c7]" />
                ) : node.isExpanded ? (
                  <ChevronDown className="w-3.5 h-3.5 shrink-0" />
                ) : (
                  <ChevronRight className="w-3.5 h-3.5 shrink-0" />
                )}
              </button>
            ) : (
              <span className="w-4 shrink-0" />
            )}

            {node.isExpanded ? (
              <FolderOpen className="w-3.5 h-3.5 text-amber-500 shrink-0" />
            ) : (
              <Folder className="w-3.5 h-3.5 text-amber-500 shrink-0" />
            )}

            <span className="truncate text-xs leading-none">{node.folder.folder_name}</span>
          </div>

          {node.folder.file_count > 0 && (
            <span className="text-[10px] font-mono text-slate-400 group-hover:text-slate-600 dark:group-hover:text-slate-300 shrink-0 ml-1">
              {node.folder.file_count}
            </span>
          )}
        </div>

        {node.isExpanded && node.children && node.children.length > 0 && (
          <div className="space-y-0.5">
            {node.children.map((child) => renderTreeNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  // ---------------------------------------------------------------------------
  // Component JSX
  // ---------------------------------------------------------------------------
  return (
    <div
      ref={containerRef}
      className="flex h-full w-full overflow-hidden bg-white dark:bg-[#1e293b] font-sans"
    >
      {/* ===================================================================== */}
      {/* PANE 1: LEFT PANE - Expandable / Collapsible Directory Tree           */}
      {/* ===================================================================== */}
      <aside
        style={{ width: `${leftWidth}px` }}
        className="flex flex-col h-full bg-white dark:bg-[#1e293b] border-r border-[#cbd5e1] dark:border-[#334155] select-none shrink-0 overflow-hidden"
      >
        {/* Tree Header */}
        <div className="p-3 border-b border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a] shrink-0 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[#0f172a] dark:text-[#f8fafc]">
              <HardDrive className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
              <span>DIRECTORY TREE</span>
            </div>
            <button
              onClick={loadRootTree}
              disabled={isTreeLoading}
              className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors cursor-pointer"
              title="Refresh Directory Tree"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isTreeLoading ? 'animate-spin text-[#0284c7]' : ''}`} />
            </button>
          </div>

          {/* Filter Folders input */}
          <div className="relative">
            <Search className="w-3 h-3 absolute left-2.5 top-2.5 text-slate-400 pointer-events-none" />
            <input
              type="text"
              value={treeSearch}
              onChange={(e) => setTreeSearch(e.target.value)}
              placeholder="Find folder..."
              className="w-full text-xs pl-7 pr-2 py-1 rounded bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] focus:outline-none focus:border-[#0284c7] text-[#0f172a] dark:text-[#f8fafc]"
            />
          </div>
        </div>

        {/* Tree Content */}
        <div className="flex-1 overflow-y-auto overflow-x-hidden p-2 space-y-0.5">
          {isTreeLoading ? (
            <div className="flex flex-col items-center justify-center py-12 text-slate-400 gap-2">
              <RefreshCw className="w-5 h-5 animate-spin text-[#0284c7]" />
              <span className="text-xs font-mono">Parsing MFT Directory Tree...</span>
            </div>
          ) : rootNodes.length === 0 ? (
            <div className="py-8 text-center text-slate-400 text-xs">
              No folders loaded. Process case evidence first.
            </div>
          ) : (
            rootNodes.map((node) => renderTreeNode(node, 0))
          )}
        </div>

        {/* Tree Footer */}
        <div className="p-2.5 border-t border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a] text-[11px] font-mono text-slate-500 dark:text-slate-400 flex items-center justify-between shrink-0">
          <span className="truncate max-w-[170px]" title={selectedFolderPath}>
            {selectedFolderPath === '.' ? 'Root (C:\\)' : selectedFolderPath}
          </span>
          <span className="text-[#0284c7] dark:text-[#38bdf8] font-bold">
            {totalFiles.toLocaleString()} items
          </span>
        </div>
      </aside>

      {/* DRAGGABLE RESIZE SPLITTER 1 (Horizontal - Left Tree vs Center/Right Panes) */}
      <ResizeHandle
        orientation="vertical"
        onMouseDown={() => setIsDraggingLeft(true)}
        onDoubleClick={() => {
          setLeftWidth(280);
          try { localStorage.removeItem('wft_filesystem_left_width'); } catch {}
        }}
        isDragging={isDraggingLeft}
        title="Drag to resize Directory Tree (double-click to reset)"
      />

      {/* ===================================================================== */}
      {/* RIGHT AREA: Split Vertically (Top File List + Bottom Preview Panes)   */}
      {/* ===================================================================== */}
      <div ref={rightContainerRef} className="flex-1 flex flex-col min-w-0 h-full overflow-hidden">
        {/* =================================================================== */}
        {/* PANE 2: CENTER-TOP PANE - High-Density FTK Imager File List Table    */}
        {/* =================================================================== */}
        <section
          style={{ height: `${topHeightPercent}%` }}
          className="flex flex-col min-h-[140px] bg-white dark:bg-[#1e293b] overflow-hidden shrink-0"
        >
          {/* File List Toolbar */}
          <div className="h-11 px-3 bg-[#f8fafc] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between gap-3 shrink-0">
            {/* Search Bar + Global vs Current Folder Toggle */}
            <div className="flex items-center gap-2 flex-1 max-w-lg">
              <div className="relative w-full">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-400 pointer-events-none" />
                <input
                  type="text"
                  value={fileSearch}
                  onChange={(e) => setFileSearch(e.target.value)}
                  placeholder={
                    isGlobalSearch
                      ? 'Global Search: Filter files across entire disk image / case...'
                      : `Search inside ${selectedFolderPath === '.' ? 'Root' : selectedFolderPath}...`
                  }
                  className="w-full text-xs pl-8 pr-3 py-1.5 rounded bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] focus:outline-none focus:border-[#0284c7] text-[#0f172a] dark:text-[#f8fafc]"
                />
              </div>

              <button
                type="button"
                onClick={() => setIsGlobalSearch((prev) => !prev)}
                className={`px-2.5 py-1 text-[11px] font-bold rounded border transition-colors shrink-0 cursor-pointer ${
                  isGlobalSearch
                    ? 'bg-[#0284c7] text-white border-[#0369a1]'
                    : 'bg-white dark:bg-[#1e293b] text-slate-700 dark:text-slate-300 border-[#cbd5e1] dark:border-[#334155] hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
                title="Toggle between searching the active folder vs global disk search"
              >
                {isGlobalSearch ? 'Global: ON' : 'Current Folder'}
              </button>
            </div>

            {/* Refresh Button */}
            <div className="flex items-center gap-2 text-xs text-slate-500 font-mono shrink-0">
              <button
                onClick={() => loadFiles(true)}
                disabled={isFilesLoading}
                className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors cursor-pointer"
                title="Refresh File List"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isFilesLoading ? 'animate-spin text-[#0284c7]' : ''}`} />
              </button>
            </div>
          </div>

          {/* Table Container with Continuous Scrolling */}
          <div
            onScroll={(e) => {
              const t = e.currentTarget;
              if (
                t.scrollHeight - t.scrollTop - t.clientHeight < 300 &&
                !isFilesLoading &&
                !isLoadingMoreFiles &&
                files.length < totalFiles
              ) {
                loadFiles(false);
              }
            }}
            className="flex-1 overflow-auto"
          >
            {isFilesLoading ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-400 gap-2">
                <RefreshCw className="w-6 h-6 animate-spin text-[#0284c7]" />
                <span className="text-xs font-mono">Querying NTFS MFT File Records...</span>
              </div>
            ) : files.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-400 text-xs">
                No files found in {selectedFolderPath}.
              </div>
            ) : (
              <>
                <table className="w-full text-left text-xs border-collapse">
                <thead className="sticky top-0 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] z-10 text-[11px] font-bold text-slate-600 dark:text-slate-300 uppercase tracking-wider select-none">
                  <tr>
                    <th className="px-3 py-2 min-w-[220px]">Name</th>
                    <th className="px-3 py-2 w-24 text-right">Size</th>
                    <th className="px-3 py-2 w-20">Type / Ext</th>
                    <th className="px-3 py-2 w-28 text-center">Allocation</th>
                    <th className="px-3 py-2 w-36">Date Modified ($SI)</th>
                    <th className="px-3 py-2 w-36">Date Created ($SI)</th>
                    <th className="px-3 py-2 w-24 text-right">MFT Entry #</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#e2e8f0] dark:divide-[#334155] font-mono">
                  {files.map((file, idx) => {
                    const isSelected = selectedFile?.full_path === file.full_path;
                    const isDir = file.is_directory;
                    const isAllocated = file.in_use;

                    return (
                      <tr
                        key={`${file.full_path}_${idx}`}
                        onClick={() => setSelectedFile(file)}
                        onContextMenu={(e) => {
                          e.preventDefault();
                          setSelectedFile(file);
                          setContextMenu({
                            position: { x: e.clientX, y: e.clientY },
                            row: {
                              ...file,
                              _table_name: 'raw_mft',
                              _row_id: file.mft_entry_number,
                              file_path: file.full_path,
                            },
                            isFolder: file.is_directory,
                            folderPath: file.is_directory ? file.full_path : undefined,
                            filePath: !file.is_directory ? file.full_path : undefined,
                            cellValue: file.file_name,
                          });
                        }}
                        onDoubleClick={() => {
                          if (isDir) {
                            handleSelectFolder(file.full_path);
                          }
                        }}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0f172a] dark:text-[#f8fafc] font-semibold'
                            : 'hover:bg-slate-50 dark:hover:bg-[#1e293b]/60 text-[#0f172a] dark:text-[#f8fafc]'
                        }`}
                      >
                        {/* Name with Folder / File / Deleted Icon */}
                        <td className="px-3 py-1.5 flex items-center gap-2 truncate max-w-[260px]">
                          {isDir ? (
                            <Folder className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                          ) : !isAllocated ? (
                            <Trash2 className="w-3.5 h-3.5 text-rose-500 shrink-0" />
                          ) : (
                            <File className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                          )}
                          <span
                            className={`truncate ${
                              !isAllocated ? 'line-through text-rose-600 dark:text-rose-400' : ''
                            }`}
                            title={file.full_path}
                          >
                            {file.file_name}
                          </span>
                        </td>

                        {/* File Size */}
                        <td className="px-3 py-1.5 text-right whitespace-nowrap text-slate-600 dark:text-slate-300">
                          {isDir ? '-' : formatFileSize(file.file_size)}
                        </td>

                        {/* Type / Ext */}
                        <td className="px-3 py-1.5 uppercase text-[11px] text-slate-500">
                          {isDir ? 'Directory' : file.extension || 'File'}
                        </td>

                        {/* Allocation Status Badge */}
                        <td className="px-3 py-1.5 text-center">
                          {isAllocated ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800">
                              Allocated
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300 border border-rose-300 dark:border-rose-800">
                              Deleted
                            </span>
                          )}
                        </td>

                        {/* Modified ($SI) */}
                        <td className="px-3 py-1.5 whitespace-nowrap text-slate-500 text-[11px]">
                          {file.si_modified || '-'}
                        </td>

                        {/* Created ($SI) */}
                        <td className="px-3 py-1.5 whitespace-nowrap text-slate-500 text-[11px]">
                          {file.si_created || '-'}
                        </td>

                        {/* MFT Entry Number */}
                        <td className="px-3 py-1.5 text-right font-bold text-[#0284c7] dark:text-[#38bdf8]">
                          {file.mft_entry_number !== null ? file.mft_entry_number : '-'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>

              {isLoadingMoreFiles && (
                <div className="py-4 text-center text-xs font-mono text-[#0284c7] flex items-center justify-center gap-2">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Loading more files in same page...</span>
                </div>
              )}
            </>
          )}
          </div>
        </section>

        {/* DRAGGABLE RESIZE SPLITTER 2 (Vertical - Top Grid vs Bottom Previews) */}
        <ResizeHandle
          orientation="horizontal"
          onMouseDown={() => setIsDraggingVertical(true)}
          onDoubleClick={() => {
            setTopHeightPercent(52);
            try { localStorage.removeItem('wft_filesystem_top_percent'); } catch {}
          }}
          isDragging={isDraggingVertical}
          title="Drag to resize File Grid & Preview Split (double-click to reset)"
        />

        {/* =================================================================== */}
        {/* BOTTOM AREA: Split Horizontally (Hex/Text/Strings + NTFS Properties) */}
        {/* =================================================================== */}
        <div
          ref={bottomContainerRef}
          className="flex-1 flex min-h-[140px] overflow-hidden bg-[#f8fafc] dark:bg-[#0f172a]"
        >
          {/* ================================================================= */}
          {/* PANE 3: CENTER-BOTTOM-LEFT - Hex / Text / Strings Viewer           */}
          {/* ================================================================= */}
          <div
            style={{ width: `${bottomLeftPercent}%` }}
            className="flex flex-col h-full bg-white dark:bg-[#1e293b] border-r border-[#cbd5e1] dark:border-[#334155] overflow-hidden shrink-0"
          >
            {/* Viewer Tab Switcher & Navigation Toolbar */}
            <div className="h-10 px-3 bg-[#f8fafc] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0 select-none">
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => setViewerTab('hex')}
                  className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold rounded cursor-pointer transition-colors ${
                    viewerTab === 'hex'
                      ? 'bg-[#0284c7] text-white'
                      : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-800'
                  }`}
                >
                  <Binary className="w-3.5 h-3.5" />
                  <span>Hex Dump</span>
                </button>

                <button
                  type="button"
                  onClick={() => setViewerTab('text')}
                  className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold rounded cursor-pointer transition-colors ${
                    viewerTab === 'text'
                      ? 'bg-[#0284c7] text-white'
                      : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-800'
                  }`}
                >
                  <FileText className="w-3.5 h-3.5" />
                  <span>Text / ASCII</span>
                </button>

                <button
                  type="button"
                  onClick={() => setViewerTab('strings')}
                  className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold rounded cursor-pointer transition-colors ${
                    viewerTab === 'strings'
                      ? 'bg-[#0284c7] text-white'
                      : 'text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-800'
                  }`}
                >
                  <Search className="w-3.5 h-3.5" />
                  <span>Extracted Strings</span>
                  {extractedStrings.length > 0 && (
                    <span className="ml-1 text-[10px] px-1.5 py-0.2 rounded-full bg-slate-200 dark:bg-slate-700 text-slate-800 dark:text-slate-200">
                      {extractedStrings.length}
                    </span>
                  )}
                </button>
              </div>

              {/* Offset Navigation (When in Hex Tab) */}
              {viewerTab === 'hex' && hexData && (
                <div className="flex items-center gap-1.5 text-xs font-mono text-slate-500">
                  <button
                    type="button"
                    onClick={() => {
                      if (selectedFile) {
                        loadFilePreviews(selectedFile, Math.max(0, hexOffset - 4096));
                      }
                    }}
                    disabled={hexOffset === 0 || isHexLoading}
                    className="p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 disabled:opacity-30 cursor-pointer"
                    title="Previous 4KB Chunk"
                  >
                    <ArrowLeft className="w-3.5 h-3.5" />
                  </button>
                  <span className="text-[11px]">
                    Offset: 0x{hexOffset.toString(16).toUpperCase().padStart(8, '0')}
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      if (selectedFile) {
                        loadFilePreviews(selectedFile, hexOffset + 4096);
                      }
                    }}
                    disabled={
                      isHexLoading ||
                      (selectedFile?.file_size !== undefined &&
                        hexOffset + 4096 >= selectedFile.file_size)
                    }
                    className="p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 disabled:opacity-30 cursor-pointer"
                    title="Next 4KB Chunk"
                  >
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>

            {/* Viewer Content Area */}
            <div className="flex-1 overflow-auto p-3 font-mono text-xs">
              {!selectedFile ? (
                <div className="flex items-center justify-center h-full text-slate-400 font-sans text-xs">
                  Select a file from the list above to view Hex, Text, or Strings.
                </div>
              ) : selectedFile.is_directory ? (
                <div className="flex flex-col items-center justify-center h-full text-slate-500 dark:text-slate-400 font-sans text-xs gap-3 p-6 text-center select-none">
                  <div className="p-3.5 rounded-full bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800 text-amber-500">
                    <Folder className="w-8 h-8" />
                  </div>
                  <div>
                    <h3 className="font-bold text-sm text-[#0f172a] dark:text-[#f8fafc]">
                      {selectedFile.file_name}
                    </h3>
                    <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                      Directory Container • {selectedFile.full_path}
                    </p>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md leading-relaxed">
                    Directories contain child files and subfolders rather than binary file streams.
                    Double-click this row to explore its contents, or review its timestamps and MFT record properties on the right.
                  </p>
                  <button
                    type="button"
                    onClick={() => handleSelectFolder(selectedFile.full_path)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-semibold shadow-2xs transition-colors cursor-pointer"
                  >
                    <FolderOpen className="w-3.5 h-3.5" />
                    <span>Open Directory ({selectedFile.file_name})</span>
                  </button>
                </div>
              ) : viewerTab === 'hex' ? (
                /* Hex Tab View */
                isHexLoading ? (
                  <div className="flex flex-col items-center justify-center h-full text-slate-400 gap-2">
                    <RefreshCw className="w-5 h-5 animate-spin text-[#0284c7]" />
                    <span>Loading 16-byte Hex representation...</span>
                  </div>
                ) : hexError ? (
                  <div className="p-4 rounded bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300 font-sans text-xs flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span>{hexError}</span>
                  </div>
                ) : !hexData || hexData.lines.length === 0 ? (
                  <div className="text-center text-slate-400 py-8">File is empty (0 bytes).</div>
                ) : (
                  <div className="space-y-0.5 select-text">
                    {hexData.lines.map((line) => (
                      <div
                        key={line.offset}
                        className="flex items-center leading-relaxed hover:bg-sky-50 dark:hover:bg-sky-950/30 px-1 rounded"
                      >
                        <span className="w-24 text-slate-400 font-bold select-none shrink-0">
                          {line.offset_hex}
                        </span>
                        <span className="w-96 text-[#0f172a] dark:text-[#f8fafc] shrink-0 font-medium tracking-wider">
                          {line.hex_bytes}
                        </span>
                        <span className="text-emerald-700 dark:text-emerald-400 whitespace-pre pl-4 border-l border-[#cbd5e1] dark:border-[#334155] select-text">
                          {line.ascii_repr}
                        </span>
                      </div>
                    ))}
                  </div>
                )
              ) : viewerTab === 'text' ? (
                /* Text / ASCII Tab View */
                isTextLoading ? (
                  <div className="flex flex-col items-center justify-center h-full text-slate-400 gap-2">
                    <RefreshCw className="w-5 h-5 animate-spin text-[#0284c7]" />
                    <span>Rendering text content preview...</span>
                  </div>
                ) : textContent ? (
                  <pre className="whitespace-pre-wrap break-all text-xs text-[#0f172a] dark:text-[#f8fafc] select-text">
                    {textContent}
                  </pre>
                ) : (
                  <div className="flex flex-col items-center justify-center h-full text-slate-400 font-sans text-xs">
                    <FileText className="w-6 h-6 mb-1 text-slate-300" />
                    <span>No readable UTF-8 text detected in this file binary.</span>
                    <button
                      type="button"
                      onClick={() => setViewerTab('hex')}
                      className="mt-2 text-[#0284c7] hover:underline"
                    >
                      Switch to Hex Dump
                    </button>
                  </div>
                )
              ) : (
                /* Extracted Strings Tab View */
                <div className="flex flex-col h-full font-sans">
                  {/* Strings Filter Bar */}
                  <div className="pb-2 mb-2 border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between gap-2 shrink-0">
                    <div className="relative flex-1">
                      <Search className="w-3 h-3 absolute left-2 top-2 text-slate-400 pointer-events-none" />
                      <input
                        type="text"
                        value={stringsFilter}
                        onChange={(e) => setStringsFilter(e.target.value)}
                        placeholder="Filter strings (e.g., http, C:\, cmd)..."
                        className="w-full text-xs pl-7 pr-2 py-1 rounded bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] focus:outline-none focus:border-[#0284c7] text-[#0f172a] dark:text-[#f8fafc]"
                      />
                    </div>
                    <button
                      type="button"
                      onClick={() => handleCopy(extractedStrings.join('\n'), 'all_strings')}
                      className="px-2 py-1 text-xs rounded bg-white hover:bg-slate-100 dark:bg-[#1e293b] dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] flex items-center gap-1 cursor-pointer shrink-0"
                    >
                      {copiedKey === 'all_strings' ? (
                        <Check className="w-3 h-3 text-emerald-600" />
                      ) : (
                        <Copy className="w-3 h-3 text-slate-500" />
                      )}
                      <span>Copy All</span>
                    </button>
                  </div>

                  {/* Strings List */}
                  <div className="flex-1 overflow-y-auto space-y-1 font-mono text-[11px] select-text">
                    {extractedStrings
                      .filter((s) => !stringsFilter || s.toLowerCase().includes(stringsFilter.toLowerCase()))
                      .map((str, idx) => (
                        <div
                          key={idx}
                          className="flex items-center gap-2 px-2 py-0.5 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
                        >
                          <span className="w-8 text-slate-400 text-right select-none shrink-0 font-normal">
                            {idx + 1}
                          </span>
                          <span className="text-[#0f172a] dark:text-[#f8fafc] break-all select-text">
                            {str}
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* DRAGGABLE RESIZE SPLITTER 3 (Horizontal - Bottom Left vs Bottom Right) */}
          <ResizeHandle
            orientation="vertical"
            onMouseDown={() => setIsDraggingBottom(true)}
            onDoubleClick={() => {
              setBottomLeftPercent(55);
              try { localStorage.removeItem('wft_filesystem_bottom_left_percent'); } catch {}
            }}
            isDragging={isDraggingBottom}
            title="Drag to resize Hex Viewer vs NTFS Properties (double-click to reset)"
          />

          {/* ================================================================= */}
          {/* PANE 4: CENTER-BOTTOM-RIGHT - NTFS & $MFT Properties Pane         */}
          {/* ================================================================= */}
          <div className="flex-1 flex flex-col h-full bg-[#f8fafc] dark:bg-[#0f172a] overflow-hidden">
            {/* Header with Bookmark Button */}
            <div className="h-10 px-3 bg-white dark:bg-[#1e293b] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0 select-none">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
                <span className="font-bold text-xs uppercase tracking-wide text-[#0f172a] dark:text-[#f8fafc]">
                  NTFS & $MFT Properties
                </span>
              </div>

              {selectedFile && (
                <button
                  type="button"
                  onClick={handleBookmarkFile}
                  disabled={isBookmarking}
                  className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded border transition-colors cursor-pointer ${
                    bookmarkSuccess
                      ? 'bg-emerald-600 text-white border-emerald-700'
                      : 'bg-white hover:bg-slate-100 dark:bg-[#0f172a] dark:hover:bg-[#1e293b] text-[#0f172a] dark:text-[#f8fafc] border-[#cbd5e1] dark:border-[#334155]'
                  }`}
                  title="Bookmark this file as Key Evidence in DuckDB"
                >
                  {bookmarkSuccess ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-white" />
                      <span>Bookmarked!</span>
                    </>
                  ) : (
                    <>
                      <Bookmark className="w-3.5 h-3.5 text-amber-500" />
                      <span>Bookmark File</span>
                    </>
                  )}
                </button>
              )}
            </div>

            {/* Properties Content */}
            <div className="flex-1 overflow-y-auto p-3 space-y-3 font-sans text-xs">
              {!selectedFile ? (
                <div className="flex items-center justify-center h-full text-slate-400 text-xs">
                  No file selected. Click an item in the file grid to view NTFS metadata.
                </div>
              ) : (
                <>
                  {/* TIMESTOMPING ALERT BANNER (If Discrepancy Found) */}
                  {timestompAnalysis?.hasTimestomp && (
                    <div className="p-3 rounded bg-rose-50 dark:bg-rose-950/50 border border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-200 space-y-1 shadow-2xs">
                      <div className="flex items-center gap-2 font-bold text-xs text-rose-700 dark:text-rose-300">
                        <ShieldAlert className="w-4 h-4 shrink-0 text-rose-600 dark:text-rose-400" />
                        <span>Timestomping Discrepancy Detected!</span>
                      </div>
                      <p className="text-[11px] leading-relaxed">
                        $STANDARD_INFORMATION ($SI) Created timestamp precedes $FILE_NAME ($FN) Created by{' '}
                        <strong>{timestompAnalysis.diffText}</strong>. This strongly indicates deliberate anti-forensic timestomping.
                      </p>
                    </div>
                  )}

                  {/* SIDE-BY-SIDE MACB TIMESTAMPS COMPARISON TABLE */}
                  <div className="bg-white dark:bg-[#1e293b] rounded border border-[#cbd5e1] dark:border-[#334155] p-3 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-extrabold uppercase tracking-wider text-slate-400">
                        MACB Timestamps ($SI vs $FN)
                      </span>
                      {!timestompAnalysis?.hasTimestomp ? (
                        <span className="text-[10px] text-emerald-600 dark:text-emerald-400 font-bold flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3" />
                          <span>Consistent Timestamps</span>
                        </span>
                      ) : (
                        <span className="text-[10px] text-rose-600 dark:text-rose-400 font-bold flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" />
                          <span>Discrepancy</span>
                        </span>
                      )}
                    </div>

                    <table className="w-full text-left font-mono text-[11px] border-collapse">
                      <thead>
                        <tr className="border-b border-[#e2e8f0] dark:border-[#334155] text-[10px] text-slate-400">
                          <th className="py-1">Attribute</th>
                          <th className="py-1">$SI (0x10)</th>
                          <th className="py-1">$FN (0x30)</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#f1f5f9] dark:divide-[#334155]/60">
                        {/* Modified (M) */}
                        <tr>
                          <td className="py-1 font-sans font-semibold text-slate-500">Modified (M)</td>
                          <td className="py-1">{selectedFile.si_modified || '-'}</td>
                          <td className="py-1 text-slate-400">{selectedFile.fn_modified || '-'}</td>
                        </tr>

                        {/* Accessed (A) */}
                        <tr>
                          <td className="py-1 font-sans font-semibold text-slate-500">Accessed (A)</td>
                          <td className="py-1">{selectedFile.si_accessed || '-'}</td>
                          <td className="py-1 text-slate-400">-</td>
                        </tr>

                        {/* MFT Record Modified (C) */}
                        <tr>
                          <td className="py-1 font-sans font-semibold text-slate-500">MFT Change (C)</td>
                          <td className="py-1">{selectedFile.si_mft_modified || '-'}</td>
                          <td className="py-1 text-slate-400">-</td>
                        </tr>

                        {/* Created / Born (B) */}
                        <tr
                          className={
                            timestompAnalysis?.hasTimestomp
                              ? 'bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 font-bold'
                              : ''
                          }
                        >
                          <td className="py-1 font-sans font-semibold">Created / Born (B)</td>
                          <td className="py-1">{selectedFile.si_created || '-'}</td>
                          <td className="py-1">{selectedFile.fn_created || '-'}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>

                  {/* MFT RECORD & SYSTEM METADATA CARD */}
                  <div className="bg-white dark:bg-[#1e293b] rounded border border-[#cbd5e1] dark:border-[#334155] p-3 space-y-2">
                    <span className="text-[10px] font-extrabold uppercase tracking-wider text-slate-400 block">
                      Record & File Identification
                    </span>

                    <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
                      <div className="p-1.5 rounded bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155]">
                        <span className="text-[10px] font-sans text-slate-400 block font-semibold">
                          MFT Record Number
                        </span>
                        <span className="font-bold text-[#0284c7] dark:text-[#38bdf8]">
                          {selectedFile.mft_entry_number !== null ? selectedFile.mft_entry_number : 'N/A'}
                        </span>
                      </div>

                      <div className="p-1.5 rounded bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155]">
                        <span className="text-[10px] font-sans text-slate-400 block font-semibold">
                          Sequence Number
                        </span>
                        <span className="font-bold">
                          {selectedFile.sequence_number !== null ? selectedFile.sequence_number : 'N/A'}
                        </span>
                      </div>

                      <div className="p-1.5 rounded bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155]">
                        <span className="text-[10px] font-sans text-slate-400 block font-semibold">
                          Allocation Status
                        </span>
                        <span
                          className={`font-bold ${
                            selectedFile.in_use ? 'text-emerald-600' : 'text-rose-600'
                          }`}
                        >
                          {selectedFile.in_use ? 'Allocated (Active)' : 'Unallocated / Deleted'}
                        </span>
                      </div>

                      <div className="p-1.5 rounded bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155]">
                        <span className="text-[10px] font-sans text-slate-400 block font-semibold">
                          File Size
                        </span>
                        <span className="font-bold">
                          {formatFileSize(selectedFile.file_size)} ({selectedFile.file_size.toLocaleString()} bytes)
                        </span>
                      </div>
                    </div>

                    <div className="p-2 rounded bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] space-y-1 font-mono text-[11px]">
                      <span className="text-[10px] font-sans text-slate-400 block font-semibold">
                        Full Evidence Path
                      </span>
                      <p className="break-all select-all text-[#0f172a] dark:text-[#f8fafc]">
                        {selectedFile.full_path}
                      </p>
                    </div>

                    {selectedFile.staged_file_path && (
                      <div className="p-2 rounded bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] space-y-1 font-mono text-[11px]">
                        <span className="text-[10px] font-sans text-slate-400 block font-semibold">
                          Extracted Staging Path
                        </span>
                        <p className="break-all select-all text-emerald-700 dark:text-emerald-400">
                          {selectedFile.staged_file_path}
                        </p>
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Native Magnet AXIOM-style Right-Click Forensic Context Menu */}
      {contextMenu && (
        <RowContextMenu
          caseId={caseId}
          position={contextMenu.position}
          onClose={() => setContextMenu(null)}
          row={contextMenu.row}
          tableName={contextMenu.row._table_name || 'raw_mft'}
          isFolder={contextMenu.isFolder}
          folderPath={contextMenu.folderPath}
          filePath={contextMenu.filePath}
          cellValue={contextMenu.cellValue}
        />
      )}
    </div>
  );
};
