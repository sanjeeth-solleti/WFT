import React, { useState, useEffect, useLayoutEffect, useRef } from 'react';
import {
  Tag,
  Bookmark,
  Trash2,
  FileDown,
  FolderArchive,
  FolderSymlink,
  FileSpreadsheet,
  FileCode,
  Copy,
  Check,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Edit3,
} from 'lucide-react';
import { apiClient, Bookmark as BookmarkItem } from '../api/client';

export interface RowContextMenuProps {
  caseId: string;
  position: { x: number; y: number };
  onClose: () => void;
  row: Record<string, any>;
  tableName?: string;
  cellValue?: unknown;
  isFolder?: boolean;
  folderPath?: string;
  filePath?: string;
  onBookmarkUpdated?: () => void;
  onExportTableCsv?: () => void;
}

export const FORENSIC_TAGS = [
  {
    id: 'Key Evidence',
    label: 'Key Evidence',
    badgeClass: 'bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950/70 dark:text-blue-300 dark:border-blue-800',
    dotClass: 'bg-blue-500',
  },
  {
    id: 'Malware',
    label: 'Malware',
    badgeClass: 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950/70 dark:text-red-300 dark:border-red-800',
    dotClass: 'bg-red-500',
  },
  {
    id: 'Initial Access',
    label: 'Initial Access',
    badgeClass: 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/70 dark:text-amber-300 dark:border-amber-800',
    dotClass: 'bg-amber-500',
  },
  {
    id: 'Persistence',
    label: 'Persistence',
    badgeClass: 'bg-purple-50 text-purple-700 border-purple-200 dark:bg-purple-950/70 dark:text-purple-300 dark:border-purple-800',
    dotClass: 'bg-purple-500',
  },
  {
    id: 'Lateral Movement',
    label: 'Lateral Movement',
    badgeClass: 'bg-cyan-50 text-cyan-700 border-cyan-200 dark:bg-cyan-950/70 dark:text-cyan-300 dark:border-cyan-800',
    dotClass: 'bg-cyan-500',
  },
  {
    id: 'Exfiltration',
    label: 'Exfiltration',
    badgeClass: 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/70 dark:text-rose-300 dark:border-rose-800',
    dotClass: 'bg-rose-500',
  },
];

export function extractRowFilePath(row: Record<string, any>, explicitPath?: string): string {
  if (explicitPath && typeof explicitPath === 'string' && explicitPath.trim()) {
    return explicitPath.trim();
  }
  if (!row) return '';
  const cand =
    row.file_path ||
    row.FilePath ||
    row.FullPath ||
    row.SourceFile ||
    row.source_file ||
    row.LocalPath ||
    row.target_path ||
    row.staged_file_path ||
    '';
  if (cand) return String(cand);

  if (row.ParentPath && row.FileName) {
    const parent = String(row.ParentPath);
    const name = String(row.FileName);
    return parent === '.' ? name : (parent.endsWith('\\') ? `${parent}${name}` : `${parent}\\${name}`);
  }
  if (row.FileName) return String(row.FileName);
  if (row.file_name) return String(row.file_name);
  if (row.SourceFilename) return String(row.SourceFilename);
  return '';
}

export function extractRowFileName(row: Record<string, any>, filePath: string): string {
  if (row.FileName) return String(row.FileName);
  if (row.file_name) return String(row.file_name);
  if (row.SourceFilename) return String(row.SourceFilename);
  if (filePath) {
    const parts = filePath.replace(/\\/g, '/').split('/');
    return parts[parts.length - 1] || filePath;
  }
  return '';
}

export const RowContextMenu: React.FC<RowContextMenuProps> = ({
  caseId,
  position,
  onClose,
  row,
  tableName,
  cellValue,
  isFolder = false,
  folderPath,
  filePath,
  onBookmarkUpdated,
  onExportTableCsv,
}) => {
  const menuRef = useRef<HTMLDivElement>(null);
  const [coords, setCoords] = useState<{ top: number; left: number }>({ top: position.y, left: position.x });

  // Custom Note Input State
  const [isNoteInputOpen, setIsNoteInputOpen] = useState(false);
  const [customNote, setCustomNote] = useState('');
  const [selectedTagForNote, setSelectedTagForNote] = useState('Key Evidence');

  // Bookmarks check state
  const [existingBookmark, setExistingBookmark] = useState<BookmarkItem | null>(null);
  const [isLoadingBookmarks, setIsLoadingBookmarks] = useState(false);

  // Status feedback / Toast state
  const [statusMsg, setStatusMsg] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);
  const [isProcessingAction, setIsProcessingAction] = useState(false);
  const [copiedAction, setCopiedAction] = useState<string | null>(null);

  const effectiveTable = tableName || String(row._table_name || row.source_table || 'evidence');
  const rowId = row._row_id !== undefined ? Number(row._row_id) : undefined;
  const detectedFilePath = extractRowFilePath(row, filePath);
  const detectedFileName = extractRowFileName(row, detectedFilePath);

  const isDirectory = Boolean(
    isFolder ||
    row.is_directory === true ||
    row.IsDirectory === true ||
    row.is_dir === true ||
    (folderPath && folderPath.length > 0)
  );
  const effectiveFolderPath = folderPath || (isDirectory ? (detectedFilePath || String(row.folder_path || '')) : '');

  // Screen clamping layout effect
  useLayoutEffect(() => {
    if (menuRef.current) {
      const rect = menuRef.current.getBoundingClientRect();
      const padding = 12;
      let left = position.x;
      let top = position.y;

      if (left + rect.width > window.innerWidth - padding) {
        left = Math.max(padding, window.innerWidth - rect.width - padding);
      }
      if (top + rect.height > window.innerHeight - padding) {
        top = Math.max(padding, window.innerHeight - rect.height - padding);
      }
      setCoords({ top, left });
    }
  }, [position, isNoteInputOpen, statusMsg]);

  // Click outside and escape key listener
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [onClose]);

  // Check if current row is already bookmarked
  useEffect(() => {
    if (!caseId) return;
    let isMounted = true;
    setIsLoadingBookmarks(true);

    apiClient
      .listBookmarks(caseId)
      .then((res) => {
        if (!isMounted) return;
        const matching = res.bookmarks.find((b) => {
          if (rowId !== undefined && b.source_row_id === rowId) {
            if (effectiveTable && b.source_table) {
              return b.source_table.toLowerCase() === effectiveTable.toLowerCase();
            }
            return true;
          }
          if (detectedFilePath && b.examiner_notes && b.examiner_notes.includes(detectedFilePath)) {
            return true;
          }
          return false;
        });
        setExistingBookmark(matching || null);
      })
      .catch((err) => {
        console.warn('Failed to load bookmarks for context menu:', err);
      })
      .finally(() => {
        if (isMounted) setIsLoadingBookmarks(false);
      });

    return () => {
      isMounted = false;
    };
  }, [caseId, effectiveTable, rowId, detectedFilePath]);

  // Tag bookmark handler
  const handleTagBookmark = async (tagName: string, notes?: string) => {
    if (!caseId) return;
    setIsProcessingAction(true);
    setStatusMsg({ type: 'info', text: `Tagging as ${tagName}...` });

    try {
      const payload = {
        source_table: effectiveTable,
        source_row_id: rowId !== undefined ? rowId : 0,
        tag_name: tagName,
        examiner_notes: notes || `Tagged as ${tagName}${detectedFilePath ? ` (${detectedFilePath})` : ''}`,
      };

      await apiClient.createBookmark(caseId, payload);
      setStatusMsg({ type: 'success', text: `Tagged row as ${tagName}` });
      if (onBookmarkUpdated) {
        onBookmarkUpdated();
      }
      setTimeout(() => {
        onClose();
      }, 600);
    } catch (err: any) {
      console.error('Error creating bookmark:', err);
      setStatusMsg({ type: 'error', text: err?.message || 'Failed to tag row' });
      setIsProcessingAction(false);
    }
  };

  // Remove bookmark handler
  const handleRemoveBookmark = async () => {
    if (!caseId) return;
    setIsProcessingAction(true);
    setStatusMsg({ type: 'info', text: 'Removing bookmark...' });

    try {
      if (existingBookmark?.bookmark_id) {
        await apiClient.deleteBookmark(caseId, existingBookmark.bookmark_id);
      } else if (rowId !== undefined) {
        await apiClient.deleteBookmarkByRow(caseId, effectiveTable, rowId);
      }
      setExistingBookmark(null);
      setStatusMsg({ type: 'success', text: 'Bookmark removed' });
      if (onBookmarkUpdated) {
        onBookmarkUpdated();
      }
      setTimeout(() => {
        onClose();
      }, 500);
    } catch (err: any) {
      console.error('Error deleting bookmark:', err);
      setStatusMsg({ type: 'error', text: err?.message || 'Failed to remove bookmark' });
      setIsProcessingAction(false);
    }
  };

  // Export / Download Raw File
  const handleDownloadRawFile = () => {
    if (!detectedFilePath) return;
    const downloadUrl = apiClient.getExportFileUrl(caseId, detectedFilePath);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = detectedFileName || 'evidence_file';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setStatusMsg({ type: 'success', text: 'Downloading raw file...' });
    setTimeout(onClose, 800);
  };

  // Export Folder as .ZIP
  const handleDownloadFolderZip = () => {
    if (!effectiveFolderPath && !detectedFilePath) return;
    const targetFolder = effectiveFolderPath || detectedFilePath;
    const downloadUrl = apiClient.getExportFolderZipUrl(caseId, targetFolder);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = `${detectedFileName || 'folder'}_export.zip`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setStatusMsg({ type: 'success', text: 'Packaging & downloading .zip...' });
    setTimeout(onClose, 800);
  };

  // Export to Custom Destination Folder (Native Windows Dialog)
  const handleSaveToFolder = async () => {
    if (!caseId) return;
    setIsProcessingAction(true);
    setStatusMsg({ type: 'info', text: 'Opening Windows folder browser...' });

    try {
      const res = await apiClient.saveToFolder(caseId, {
        file_path: isDirectory ? effectiveFolderPath : detectedFilePath,
        is_folder: isDirectory,
        table_name: tableName,
        row_id: rowId,
      });

      if (res.cancelled) {
        setStatusMsg({ type: 'info', text: 'Export cancelled' });
        setIsProcessingAction(false);
        setTimeout(onClose, 600);
        return;
      }

      if (res.success) {
        setStatusMsg({
          type: 'success',
          text: `Saved to: ${res.saved_path || res.destination_folder}`,
        });
        setTimeout(onClose, 1500);
      }
    } catch (err: any) {
      console.error('Save to folder error:', err);
      setStatusMsg({ type: 'error', text: err?.message || 'Failed to export to custom folder' });
      setIsProcessingAction(false);
    }
  };

  // Export Table to CSV
  const handleExportTableToCsv = () => {
    if (onExportTableCsv) {
      onExportTableCsv();
      setStatusMsg({ type: 'success', text: 'Exported table to CSV' });
      setTimeout(onClose, 600);
      return;
    }

    if (effectiveTable) {
      const csvUrl = apiClient.getTableExportCsvUrl(caseId, effectiveTable);
      const a = document.createElement('a');
      a.href = csvUrl;
      a.download = `${effectiveTable}_export.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setStatusMsg({ type: 'success', text: 'Downloading CSV export...' });
      setTimeout(onClose, 800);
    }
  };

  // Export Row as JSON
  const handleExportRowAsJson = () => {
    try {
      const jsonStr = JSON.stringify(row, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${effectiveTable}_row_${rowId ?? 'record'}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setStatusMsg({ type: 'success', text: 'Downloaded row JSON' });
      setTimeout(onClose, 600);
    } catch (err: any) {
      setStatusMsg({ type: 'error', text: 'Failed to serialize row JSON' });
    }
  };

  // Quick Copy
  const handleCopy = async (text: string, actionId: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedAction(actionId);
      setStatusMsg({ type: 'success', text: 'Copied to clipboard!' });
      setTimeout(() => {
        setCopiedAction(null);
        onClose();
      }, 700);
    } catch (err) {
      console.error('Clipboard copy failed:', err);
    }
  };

  const hasFilePath = Boolean(detectedFilePath && detectedFilePath.length > 0 && !detectedFilePath.startsWith('[DIRECTORY]'));
  const canExportFolder = isDirectory || Boolean(effectiveFolderPath);

  return (
    <div
      ref={menuRef}
      style={{
        position: 'fixed',
        top: coords.top,
        left: coords.left,
        zIndex: 99999,
      }}
      className="w-72 bg-white dark:bg-[#0f172a] rounded-lg shadow-2xl border border-slate-200 dark:border-[#334155] py-1 text-xs select-none animate-in fade-in zoom-in-95 duration-100 flex flex-col font-sans"
    >
      {/* Toast / Status banner */}
      {statusMsg && (
        <div
          className={`mx-2 my-1.5 px-2.5 py-1.5 rounded flex items-center gap-2 text-[11px] font-medium leading-tight ${
            statusMsg.type === 'success'
              ? 'bg-emerald-50 text-emerald-800 border border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800'
              : statusMsg.type === 'error'
              ? 'bg-rose-50 text-rose-800 border border-rose-200 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-800'
              : 'bg-sky-50 text-sky-800 border border-sky-200 dark:bg-sky-950/60 dark:text-sky-300 dark:border-sky-800'
          }`}
        >
          {isProcessingAction ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0 text-[#0284c7]" />
          ) : statusMsg.type === 'success' ? (
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
          ) : (
            <AlertCircle className="w-3.5 h-3.5 text-rose-500 shrink-0" />
          )}
          <span className="truncate">{statusMsg.text}</span>
        </div>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* SECTION 1: FORENSIC TAGS & BOOKMARKS                                  */}
      {/* --------------------------------------------------------------------- */}
      <div className="px-3 py-1 text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider flex items-center justify-between">
        <span className="flex items-center gap-1.5">
          <Bookmark className="w-3 h-3 text-[#0284c7]" />
          <span>Forensic Tags & Bookmarks</span>
        </span>
        {existingBookmark && (
          <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800 font-mono lowercase">
            tagged
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 gap-1 px-2 py-1">
        {FORENSIC_TAGS.map((tag) => {
          const isTaggedWithThis = existingBookmark?.tag_name === tag.id;
          return (
            <button
              key={tag.id}
              disabled={isProcessingAction}
              onClick={() => handleTagBookmark(tag.id)}
              className={`flex items-center gap-1.5 px-2 py-1 rounded text-[11px] font-semibold border transition-all cursor-pointer ${
                isTaggedWithThis
                  ? 'border-[#0284c7] bg-sky-50 dark:bg-sky-950/50 text-[#0284c7] shadow-2xs'
                  : `${tag.badgeClass} hover:opacity-90`
              }`}
            >
              <span className={`w-2 h-2 rounded-full ${tag.dotClass} shrink-0`} />
              <span className="truncate">{tag.label}</span>
            </button>
          );
        })}
      </div>

      {/* Bookmark with custom note button / inline form */}
      {!isNoteInputOpen ? (
        <button
          disabled={isProcessingAction}
          onClick={() => setIsNoteInputOpen(true)}
          className="flex items-center gap-2 px-3 py-1.5 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#1e293b] hover:text-[#0284c7] transition-colors cursor-pointer text-left mx-1 rounded"
        >
          <Edit3 className="w-3.5 h-3.5 text-slate-400" />
          <span>Bookmark with Custom Note...</span>
        </button>
      ) : (
        <div className="mx-2 my-1 p-2 rounded bg-slate-50 dark:bg-[#1e293b]/70 border border-[#cbd5e1] dark:border-[#334155] flex flex-col gap-1.5">
          <label className="text-[10px] font-semibold text-slate-500 uppercase">Examiner Note:</label>
          <textarea
            autoFocus
            rows={2}
            value={customNote}
            onChange={(e) => setCustomNote(e.target.value)}
            placeholder="Analysis findings, IOC notes, artifact context..."
            className="w-full text-xs p-1.5 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f172a] text-[#0f172a] dark:text-[#f8fafc] resize-none focus:outline-hidden focus:border-[#0284c7]"
          />
          <div className="flex items-center justify-between gap-1 mt-1">
            <select
              value={selectedTagForNote}
              onChange={(e) => setSelectedTagForNote(e.target.value)}
              className="text-[11px] px-1.5 py-1 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f172a] text-slate-700 dark:text-slate-200"
            >
              {FORENSIC_TAGS.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.label}
                </option>
              ))}
            </select>
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => setIsNoteInputOpen(false)}
                className="px-2 py-1 text-[11px] rounded text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => handleTagBookmark(selectedTagForNote, customNote)}
                className="px-2.5 py-1 text-[11px] font-bold rounded bg-[#0284c7] text-white hover:bg-[#0369a1] shadow-2xs"
              >
                Save
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Remove Bookmark / Tag (Shown if row is bookmarked) */}
      {existingBookmark && (
        <button
          disabled={isProcessingAction}
          onClick={handleRemoveBookmark}
          className="flex items-center gap-2 px-3 py-1.5 text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/40 transition-colors cursor-pointer text-left mx-1 rounded font-medium"
        >
          <Trash2 className="w-3.5 h-3.5 text-rose-500" />
          <span>Remove Bookmark / Tag ({existingBookmark.tag_name})</span>
        </button>
      )}

      <div className="my-1 border-b border-slate-200 dark:border-[#1e293b]" />

      {/* --------------------------------------------------------------------- */}
      {/* SECTION 2: FORENSIC EXPORT OPTIONS                                    */}
      {/* --------------------------------------------------------------------- */}
      <div className="px-3 py-1 text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
        <FileDown className="w-3 h-3 text-[#0284c7]" />
        <span>Forensic Export Options</span>
      </div>

      {/* Export / Download Raw File */}
      <button
        disabled={!hasFilePath || isProcessingAction}
        onClick={handleDownloadRawFile}
        title={hasFilePath ? detectedFilePath : 'No raw file path associated with this record'}
        className={`flex items-center gap-2 px-3 py-1.5 text-left mx-1 rounded transition-colors ${
          hasFilePath && !isProcessingAction
            ? 'text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#1e293b] hover:text-[#0284c7] cursor-pointer'
            : 'text-slate-400 dark:text-slate-600 cursor-not-allowed opacity-60'
        }`}
      >
        <FileDown className="w-3.5 h-3.5 text-[#0284c7] shrink-0" />
        <span className="truncate">
          Export / Download Raw File {detectedFileName ? `(${detectedFileName})` : ''}
        </span>
      </button>

      {/* Export File / Folder to Custom Destination (Windows FolderPicker) */}
      <button
        disabled={isProcessingAction}
        onClick={handleSaveToFolder}
        className="flex items-center gap-2 px-3 py-1.5 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#1e293b] hover:text-[#0284c7] transition-colors cursor-pointer text-left mx-1 rounded"
      >
        <FolderSymlink className="w-3.5 h-3.5 text-amber-500 shrink-0" />
        <span>Export File / Folder to Custom Destination...</span>
      </button>

      {/* Export Folder as .ZIP Archive (Enabled for directories) */}
      <button
        disabled={!canExportFolder || isProcessingAction}
        onClick={handleDownloadFolderZip}
        title={canExportFolder ? `Package ${effectiveFolderPath} as .zip` : 'Only enabled for directory rows'}
        className={`flex items-center gap-2 px-3 py-1.5 text-left mx-1 rounded transition-colors ${
          canExportFolder && !isProcessingAction
            ? 'text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#1e293b] hover:text-[#0284c7] cursor-pointer'
            : 'text-slate-400 dark:text-slate-600 cursor-not-allowed opacity-60'
        }`}
      >
        <FolderArchive className="w-3.5 h-3.5 text-amber-500 shrink-0" />
        <span className="truncate">Export Folder as .ZIP Archive</span>
      </button>

      {/* Export Current Table View to CSV */}
      <button
        disabled={isProcessingAction}
        onClick={handleExportTableToCsv}
        className="flex items-center gap-2 px-3 py-1.5 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#1e293b] hover:text-[#0284c7] transition-colors cursor-pointer text-left mx-1 rounded"
      >
        <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
        <span>Export Current Table View to CSV</span>
      </button>

      {/* Export Selected Row as JSON */}
      <button
        disabled={isProcessingAction}
        onClick={handleExportRowAsJson}
        className="flex items-center gap-2 px-3 py-1.5 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#1e293b] hover:text-[#0284c7] transition-colors cursor-pointer text-left mx-1 rounded"
      >
        <FileCode className="w-3.5 h-3.5 text-indigo-500 shrink-0" />
        <span>Export Selected Row as JSON</span>
      </button>

      <div className="my-1 border-b border-slate-200 dark:border-[#1e293b]" />

      {/* --------------------------------------------------------------------- */}
      {/* SECTION 3: QUICK COPY ACTIONS                                         */}
      {/* --------------------------------------------------------------------- */}
      <div className="px-3 py-1 text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
        <Copy className="w-3 h-3 text-[#0284c7]" />
        <span>Quick Copy Actions</span>
      </div>

      {/* Copy Cell Value */}
      <button
        onClick={() => handleCopy(String(cellValue ?? ''), 'cell')}
        className="flex items-center justify-between px-3 py-1.5 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#1e293b] hover:text-[#0284c7] transition-colors cursor-pointer text-left mx-1 rounded"
      >
        <span className="flex items-center gap-2 truncate">
          {copiedAction === 'cell' ? (
            <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
          ) : (
            <Copy className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          )}
          <span className="truncate">Copy Cell Value</span>
        </span>
        {cellValue !== undefined && cellValue !== null && (
          <span className="text-[10px] text-slate-400 font-mono truncate max-w-[90px] ml-1">
            "{String(cellValue)}"
          </span>
        )}
      </button>

      {/* Copy File Path / Source Path */}
      <button
        disabled={!detectedFilePath}
        onClick={() => handleCopy(detectedFilePath, 'path')}
        className={`flex items-center justify-between px-3 py-1.5 text-left mx-1 rounded transition-colors ${
          detectedFilePath
            ? 'text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#1e293b] hover:text-[#0284c7] cursor-pointer'
            : 'text-slate-400 dark:text-slate-600 cursor-not-allowed opacity-60'
        }`}
      >
        <span className="flex items-center gap-2 truncate">
          {copiedAction === 'path' ? (
            <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
          ) : (
            <Copy className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          )}
          <span className="truncate">Copy File Path / Source Path</span>
        </span>
      </button>

      {/* Copy Full Row (JSON) */}
      <button
        onClick={() => handleCopy(JSON.stringify(row, null, 2), 'row')}
        className="flex items-center justify-between px-3 py-1.5 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#1e293b] hover:text-[#0284c7] transition-colors cursor-pointer text-left mx-1 rounded"
      >
        <span className="flex items-center gap-2 truncate">
          {copiedAction === 'row' ? (
            <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
          ) : (
            <Copy className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          )}
          <span className="truncate">Copy Full Row (JSON)</span>
        </span>
      </button>
    </div>
  );
};
