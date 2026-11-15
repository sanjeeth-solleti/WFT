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
} from 'lucide-react';
import {
  apiClient,
  FileSystemFolderItem,
  FileSystemFileItem,
  HexViewerResponse,
} from '../api/client';
import { ResizeHandle } from './ResizeHandle';
import { RowContextMenu } from './RowContextMenu';

interface FileSystemViewProps {
  caseId: string;
}

interface TreeNode {
  id: string;
  label: string;
  nodeType: 'image' | 'partition' | 'volume' | 'root' | 'folder' | 'unallocated';
  folder: FileSystemFolderItem;
  children?: TreeNode[];
  isExpanded: boolean;
  isLoading: boolean;
  isLoaded: boolean;
}

export const FileSystemView: React.FC<FileSystemViewProps> = ({ caseId }) => {
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
  const [selectedNodeLabel, setSelectedNodeLabel] = useState<string>('[root] (Partition 2)');

  // File List State
  const [files, setFiles] = useState<FileSystemFileItem[]>([]);
  const [totalFiles, setTotalFiles] = useState(0);
  const [isFilesLoading, setIsFilesLoading] = useState(false);
  const [fileSearch, setFileSearch] = useState('');
  const [isGlobalSearch, setIsGlobalSearch] = useState(false);
  const [isLoadingMoreFiles, setIsLoadingMoreFiles] = useState(false);
  const pageSize = 150;
  const [selectedFile, setSelectedFile] = useState<FileSystemFileItem | null>(null);

  // Full-Width Bottom Viewer Tabs (Hex | Text | Strings | NTFS & $MFT Properties)
  const [viewerTab, setViewerTab] = useState<'hex' | 'text' | 'strings' | 'properties'>('hex');
  const [hexData, setHexData] = useState<HexViewerResponse | null>(null);
  const [hexOffset, setHexOffset] = useState(0);
  const [isHexLoading, setIsHexLoading] = useState(false);
  const [hexError, setHexError] = useState<string | null>(null);
  const [textContent, setTextContent] = useState<string | null>(null);
  const [isTextLoading, setIsTextLoading] = useState(false);
  const [extractedStrings, setExtractedStrings] = useState<string[]>([]);
  const [stringsFilter, setStringsFilter] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isBookmarking, setIsBookmarking] = useState(false);
  const [bookmarkSuccess, setBookmarkSuccess] = useState(false);

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

  // Build Exact FTK Imager Evidence Tree
  const loadRootTree = useCallback(async () => {
    if (!caseId) return;
    setIsTreeLoading(true);
    try {
      const [p2Res, p1Res] = await Promise.all([
        apiClient.getFilesystemTree(caseId, '.'),
        apiClient.getFilesystemTree(caseId, '.\\__PART1__').catch(() => ({ folders: [], total_folders: 0 })),
      ]);

      const makeFolderNode = (f: FileSystemFolderItem): TreeNode => ({
        id: f.folder_path,
        label: f.folder_name,
        nodeType: 'folder',
        folder: f,
        isExpanded: false,
        isLoading: false,
        isLoaded: false,
      });

      const dummyFolder = (path: string, name: string): FileSystemFolderItem => ({
        folder_name: name,
        folder_path: path,
        parent_path: '',
        mft_entry_number: 5,
        sequence_number: 1,
        in_use: true,
        file_count: 0,
        is_directory: true,
      });

      const p1Children = (p1Res.folders || []).map(makeFolderNode);
      const p2Children = (p2Res.folders || []).map(makeFolderNode);

      const imageRoot: TreeNode = {
        id: 'image_root',
        label: `${caseId} [Disk Image]`,
        nodeType: 'image',
        folder: dummyFolder('.', caseId),
        isExpanded: true,
        isLoading: false,
        isLoaded: true,
        children: [
          {
            id: 'part1',
            label: 'Partition 1 [100MB]',
            nodeType: 'partition',
            folder: dummyFolder('.\\__PART1__', 'Partition 1 [100MB]'),
            isExpanded: true,
            isLoading: false,
            isLoaded: true,
            children: [
              {
                id: 'part1_ntfs',
                label: 'System Reserved [NTFS]',
                nodeType: 'volume',
                folder: dummyFolder('.\\__PART1__', 'System Reserved [NTFS]'),
                isExpanded: true,
                isLoading: false,
                isLoaded: true,
                children: [
                  {
                    id: 'part1_root',
                    label: '[root]',
                    nodeType: 'root',
                    folder: dummyFolder('.\\__PART1__', '[root]'),
                    isExpanded: true,
                    isLoading: false,
                    isLoaded: true,
                    children: p1Children,
                  },
                ],
              },
            ],
          },
          {
            id: 'part2',
            label: 'Partition 2 [20378MB]',
            nodeType: 'partition',
            folder: dummyFolder('.', 'Partition 2 [20378MB]'),
            isExpanded: true,
            isLoading: false,
            isLoaded: true,
            children: [
              {
                id: 'part2_ntfs',
                label: 'NONAME [NTFS]',
                nodeType: 'volume',
                folder: dummyFolder('.', 'NONAME [NTFS]'),
                isExpanded: true,
                isLoading: false,
                isLoaded: true,
                children: [
                  {
                    id: 'part2_root',
                    label: '[root]',
                    nodeType: 'root',
                    folder: dummyFolder('.', '[root]'),
                    isExpanded: true,
                    isLoading: false,
                    isLoaded: true,
                    children: p2Children,
                  },
                ],
              },
            ],
          },
          {
            id: 'unpartitioned',
            label: 'Unpartitioned Space [basic disk]',
            nodeType: 'unallocated',
            folder: dummyFolder('', 'Unpartitioned Space'),
            isExpanded: false,
            isLoading: false,
            isLoaded: true,
          },
        ],
      };

      setRootNodes([imageRoot]);
    } catch (err) {
      console.error('Failed to load FTK Evidence Tree:', err);
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
          if (willExpand && !node.isLoaded && node.nodeType === 'folder') {
            try {
              const res = await apiClient.getFilesystemTree(caseId, node.folder.folder_path);
              children = (res.folders || []).map((f) => ({
                id: f.folder_path,
                label: f.folder_name,
                nodeType: 'folder',
                folder: f,
                isExpanded: false,
                isLoading: false,
                isLoaded: false,
              }));
            } catch {}
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

  const loadFiles = useCallback(
    async (reset: boolean = true) => {
      if (!caseId) return;
      if (!selectedFolderPath && !isGlobalSearch) {
        setFiles([]);
        setTotalFiles(0);
        return;
      }
      if (reset) setIsFilesLoading(true);
      else setIsLoadingMoreFiles(true);

      try {
        const res = await apiClient.getFilesystemFiles(caseId, {
          folder_path: isGlobalSearch ? '' : selectedFolderPath,
          search: fileSearch.trim() || undefined,
          limit: pageSize,
          offset: reset ? 0 : files.length,
        });
        const list = res.files || [];
        if (reset) {
          setFiles(list);
          setSelectedFile(list.length > 0 ? list[0] : null);
        } else {
          setFiles((prev) => [...prev, ...list]);
        }
        setTotalFiles(res.total_files || 0);
      } catch (err) {
        console.error('Failed to load files:', err);
      } finally {
        setIsFilesLoading(false);
        setIsLoadingMoreFiles(false);
      }
    },
    [caseId, selectedFolderPath, isGlobalSearch, fileSearch, files.length]
  );

  useEffect(() => {
    loadFiles(true);
  }, [caseId, selectedFolderPath, isGlobalSearch, fileSearch]);

  const loadFilePreviews = useCallback(
    async (file: FileSystemFileItem, offset: number = 0) => {
      if (file.is_directory) {
        setHexData(null);
        setTextContent(null);
        setExtractedStrings([]);
        return;
      }
      const targetPath = file.staged_file_path || file.full_path || file.file_name;
      if (!targetPath) return;

      setIsHexLoading(true);
      setHexError(null);
      try {
        const hexRes = await apiClient.getHexViewer(caseId, targetPath, offset, 4096);
        setHexData(hexRes);
        setHexOffset(offset);
        const asciiChunk = (hexRes.lines || []).map((l) => l.ascii_repr).join('');
        const matches = asciiChunk.match(/[A-Za-z0-9_\-\.\/\\: @#$%^&*()+=]{4,}/g) || [];
        setExtractedStrings(Array.from(new Set(matches.map((s) => s.trim()))).filter((s) => s.length >= 4));
      } catch (err: any) {
        setHexError(err.message || 'Raw sector bytes not staged for this file');
        setHexData(null);
      } finally {
        setIsHexLoading(false);
      }

      setIsTextLoading(true);
      try {
        const contentRes = await apiClient.getFileContent(caseId, targetPath, 500000);
        setTextContent(contentRes.text_content || null);
      } catch {
        setTextContent(null);
      } finally {
        setIsTextLoading(false);
      }
    },
    [caseId]
  );

  useEffect(() => {
    if (selectedFile) loadFilePreviews(selectedFile, 0);
  }, [selectedFile, loadFilePreviews]);

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
    const hasKids = (node.children && node.children.length > 0) || (!node.isLoaded && node.nodeType === 'folder');

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
          ) : node.nodeType === 'unallocated' ? (
            <Database className="w-3.5 h-3.5 text-slate-400 shrink-0" />
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
            <button onClick={loadRootTree} className="p-0.5 text-slate-400 hover:text-slate-700 cursor-pointer">
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
                  {files.length === 0 && !isFilesLoading ? (
                    <tr>
                      <td colSpan={6} className="py-10 text-center text-slate-400 text-xs">
                        {selectedFolderPath === ''
                          ? 'Unpartitioned space contains raw unallocated disk sectors.'
                          : 'No files in this directory.'}
                      </td>
                    </tr>
                  ) : (
                    files.map((file, idx) => {
                      const isSelected = selectedFile?.full_path === file.full_path;
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
                  className="px-2 py-0.5 text-[11px] font-semibold rounded bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] hover:bg-slate-100 flex items-center gap-1 cursor-pointer"
                >
                  <Bookmark className="w-3 h-3 text-amber-500" />
                  <span>{bookmarkSuccess ? 'Bookmarked!' : 'Bookmark'}</span>
                </button>
              )}
            </div>

            <div className="flex-1 overflow-auto p-3 font-mono text-xs">
              {!selectedFile ? (
                <div className="flex items-center justify-center h-full text-slate-400 font-sans text-xs">
                  Select an item in the File List to inspect Hex bytes, Text, or NTFS $MFT attributes.
                </div>
              ) : viewerTab === 'properties' ? (
                <div className="grid grid-cols-3 gap-3 font-sans text-xs max-w-4xl">
                  <div className="p-2.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a]">
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">MFT Record #</span>
                    <span className="font-mono font-bold text-[#0284c7]">{selectedFile.mft_entry_number ?? 'N/A'}</span>
                  </div>
                  <div className="p-2.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a]">
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">Sequence #</span>
                    <span className="font-mono font-bold">{selectedFile.sequence_number ?? 'N/A'}</span>
                  </div>
                  <div className="p-2.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a]">
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">Allocation Status</span>
                    <span className={`font-bold ${selectedFile.in_use ? 'text-emerald-600' : 'text-rose-600'}`}>
                      {selectedFile.in_use ? 'Allocated (Active)' : 'Deleted / Unallocated'}
                    </span>
                  </div>
                  <div className="col-span-3 p-2.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a] font-mono text-[11px]">
                    <span className="text-[10px] font-sans text-slate-400 font-bold uppercase block">Full Evidence Path</span>
                    {selectedFile.full_path.replace('.\\__PART1__', 'Partition 1 [100MB]')}
                  </div>
                </div>
              ) : viewerTab === 'hex' ? (
                hexData && hexData.lines.length > 0 ? (
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
                ) : (
                  <div className="text-slate-400 font-sans text-xs py-6 text-center">
                    {selectedFile.is_directory
                      ? `Folder "${selectedFile.file_name}" — double-click in the File List to open, or switch to the "NTFS & $MFT Properties" tab.`
                      : hexError || 'No binary stream available for this entry.'}
                  </div>
                )
              ) : viewerTab === 'text' ? (
                <pre className="whitespace-pre-wrap text-xs">{textContent || 'No readable UTF-8 text in this file.'}</pre>
              ) : (
                <div className="space-y-1 text-[11px]">
                  {extractedStrings.map((s, i) => (
                    <div key={i}>{s}</div>
                  ))}
                </div>
              )}
            </div>
          </section>
        </div>
      </div>

      {/* FTK-STYLE BOTTOM STATUS BAR */}
      <div className="h-6 px-3 bg-[#f1f5f9] dark:bg-[#0f172a] border-t border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between text-[11px] font-mono text-slate-600 dark:text-slate-300 shrink-0">
        <span>
          Listed: {files.length.toLocaleString()} / {totalFiles.toLocaleString()} | Selected:{' '}
          {selectedFile ? selectedFile.file_name : 'None'}
        </span>
        <span>{selectedFolderPath.startsWith('.\\__PART1__')
          ? `${caseId}/Partition 1 [100MB]/System Reserved [NTFS]/[root]${selectedFolderPath.replace('.\\__PART1__', '').replace(/\\/g, '/')}`
          : `${caseId}/Partition 2 [20378MB]/NONAME [NTFS]/[root]${selectedFolderPath === '.' ? '' : selectedFolderPath.slice(1).replace(/\\/g, '/')}`}</span>
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
        />
      )}
    </div>
  );
};