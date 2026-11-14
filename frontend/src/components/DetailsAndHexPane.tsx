import React, { useState, useEffect, useRef } from 'react';
import {
  FileText,
  Binary,
  Bookmark,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  Eye,
  Info,
  Layers,
  HardDrive,
  ArrowLeft,
  ArrowRight,
  Image as ImageIcon,
  Loader2,
  Download,
  ExternalLink,
  Clock,
} from 'lucide-react';
import {
  apiClient,
  HexViewerResponse,
  BookmarkCreateRequest,
  FileContentResponse,
} from '../api/client';
import { useVerticalResizable, ResizeHandle } from './ResizeHandle';

interface DetailsAndHexPaneProps {
  caseId: string;
  tableName: string | null;
  selectedRow: Record<string, unknown> | null;
  onInspectEntity?: (entityValue: string) => void;
  onBookmarkCreated?: () => void;
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
  width?: number;
}

export const DetailsAndHexPane: React.FC<DetailsAndHexPaneProps> = ({
  caseId,
  tableName,
  selectedRow,
  onInspectEntity,
  onBookmarkCreated,
  width,
}) => {
  // Preview Tabs: 'hex' | 'media' | 'ocr'
  const [previewTab, setPreviewTab] = useState<'hex' | 'media' | 'ocr'>('hex');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Sections collapse state in Details
  const [isArtifactInfoOpen, setIsArtifactInfoOpen] = useState(true);
  const [isEvidenceInfoOpen, setIsEvidenceInfoOpen] = useState(true);
  const [isPrefetchHistoryOpen, setIsPrefetchHistoryOpen] = useState(true);

  // Bookmark inline state
  const [isBookmarking, setIsBookmarking] = useState(false);
  const [selectedTag, setSelectedTag] = useState('Key Evidence');
  const [notes, setNotes] = useState('');
  const [bookmarkSuccess, setBookmarkSuccess] = useState(false);

  // Hex Viewer State
  const [hexData, setHexData] = useState<HexViewerResponse | null>(null);
  const [hexOffset, setHexOffset] = useState(0);
  const [hexError, setHexError] = useState<string | null>(null);
  const [isLoadingHex, setIsLoadingHex] = useState(false);

  // Document & Media Preview State
  const [fileContent, setFileContent] = useState<FileContentResponse | null>(null);
  const [isLoadingContent, setIsLoadingContent] = useState(false);
  const [contentError, setContentError] = useState<string | null>(null);

  // Vertical split between Top Preview and Bottom Details
  const containerRef = useRef<HTMLElement>(null);
  const {
    percent: previewPercent,
    isDragging: isDraggingVertical,
    handleMouseDown: handleVerticalMouseDown,
    resetPercent: resetVerticalPercent,
  } = useVerticalResizable({
    initialPercent: 48,
    minPercent: 15,
    maxPercent: 85,
    storageKey: 'wft_details_preview_percent',
    containerRef,
  });

  // Extract source file path from row if available
  const detectedFilePath = (() => {
    if (!selectedRow) return '';
    return (
      (selectedRow.carved_path as string) ||
      (selectedRow.carved_file_path as string) ||
      (selectedRow.thumbnail_path as string) ||
      (selectedRow.file_path as string) ||
      (selectedRow.FullPath as string) ||
      (selectedRow.target_path as string) ||
      (selectedRow.LocalPath as string) ||
      (selectedRow.Path as string) ||
      (selectedRow.SourceFile as string) ||
      (selectedRow.source_file as string) ||
      (selectedRow.SourceFilename as string) ||
      (selectedRow.ExecutableInfo as string) ||
      (selectedRow.ParentPath && selectedRow.FileName ? `${selectedRow.ParentPath}\\${selectedRow.FileName}` : '') ||
      (selectedRow.file_name as string) ||
      (selectedRow.FileName as string) ||
      ''
    );
  })();

  const ocrText = selectedRow ? String(selectedRow.ocr_extracted_text || selectedRow.text || '') : '';
  const isDocumentOrMedia = Boolean(
    selectedRow && (
      Boolean(selectedRow.carved_path) ||
      Boolean(selectedRow.carved_file_path) ||
      Boolean(selectedRow.thumbnail_path) ||
      Boolean(selectedRow.file_name) ||
      Boolean(selectedRow.FileName) ||
      Boolean(selectedRow.file_path) ||
      Boolean(detectedFilePath.match(/\.(txt|log|csv|tsv|ini|inf|bat|cmd|ps1|reg|py|js|json|xml|html|htm|css|yaml|yml|md|pdf|doc|docx|xls|xlsx|ppt|pptx|png|jpg|jpeg|gif|bmp|webp|ico|svg|mp4|webm|mp3|wav|chm)$/i))
    )
  );

  // Auto-switch preview tab if document/media or OCR is available
  useEffect(() => {
    if (ocrText && !detectedFilePath) {
      setPreviewTab('ocr');
    } else if (isDocumentOrMedia) {
      setPreviewTab('media');
    } else {
      setPreviewTab('hex');
    }
  }, [selectedRow?._row_id]);

  // Fetch Document & Media content
  useEffect(() => {
    if (!caseId || !detectedFilePath) {
      setFileContent(null);
      return;
    }

    const abortController = new AbortController();
    setIsLoadingContent(true);
    setContentError(null);

    apiClient
      .getFileContent(caseId, detectedFilePath, 2000000, abortController.signal)
      .then((res) => {
        setFileContent(res);
      })
      .catch((err) => {
        if (err?.name === 'AbortError' || err?.message?.includes('aborted')) {
          return;
        }
        setContentError(err instanceof Error ? err.message : String(err));
        setFileContent(null);
      })
      .finally(() => {
        if (!abortController.signal.aborted) {
          setIsLoadingContent(false);
        }
      });

    return () => {
      abortController.abort();
    };
  }, [caseId, detectedFilePath]);

  // Fetch Hex bytes whenever row or offset changes
  useEffect(() => {
    if (!caseId || !detectedFilePath) {
      setHexData(null);
      return;
    }

    const abortController = new AbortController();
    setIsLoadingHex(true);
    setHexError(null);

    apiClient
      .getHexViewer(caseId, detectedFilePath, hexOffset, 4096, abortController.signal)
      .then((res) => {
        setHexData(res);
      })
      .catch((err) => {
        if (err?.name === 'AbortError' || err?.message?.includes('aborted')) {
          return;
        }
        setHexError(err instanceof Error ? err.message : String(err));
        setHexData(null);
      })
      .finally(() => {
        if (!abortController.signal.aborted) {
          setIsLoadingHex(false);
        }
      });

    return () => {
      abortController.abort();
    };
  }, [caseId, detectedFilePath, hexOffset]);

  const handleCopy = (key: string, val: unknown) => {
    navigator.clipboard.writeText(String(val ?? ''));
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  const handleCreateBookmark = async () => {
    if (!tableName || !selectedRow) return;
    const rowId = Number(selectedRow._row_id || 1);

    try {
      const payload: BookmarkCreateRequest = {
        source_table: tableName,
        source_row_id: rowId,
        tag_name: selectedTag,
        examiner_notes: notes.trim() || undefined,
      };

      await apiClient.createBookmark(caseId, payload);
      setBookmarkSuccess(true);
      setIsBookmarking(false);
      setNotes('');
      if (onBookmarkCreated) onBookmarkCreated();
      setTimeout(() => setBookmarkSuccess(false), 2000);
    } catch (err: unknown) {
      console.error('Bookmark creation failed:', err);
    }
  };

  // Split attributes into Artifact Information & Evidence Information
  const allKeys = selectedRow ? Object.keys(selectedRow) : [];
  const artifactInfoKeys = allKeys.filter(
    (k) =>
      k === '_row_id' ||
      k.toLowerCase().includes('time') ||
      k.toLowerCase().includes('date') ||
      k.toLowerCase().includes('run') ||
      k.toLowerCase().includes('record') ||
      k.toLowerCase().includes('channel') ||
      k.toLowerCase().includes('eventid') ||
      k.toLowerCase().includes('level') ||
      k.toLowerCase().includes('source')
  );
  const evidenceInfoKeys = allKeys.filter((k) => !artifactInfoKeys.includes(k));

  // Prefetch Execution History Extraction (Windows 8+ records up to 8 runs)
  const prefetchRuns = (() => {
    if (!selectedRow) return null;
    const lowerKeys = Object.keys(selectedRow).map((k) => k.toLowerCase());
    const hasLastRun = lowerKeys.includes('lastrun');
    const hasPrevRun = lowerKeys.some((k) => k.startsWith('previousrun'));
    const isPecmd = tableName === 'raw_pecmd' || tableName === 'raw_pecmd_timeline';
    if (!hasLastRun && !hasPrevRun && !isPecmd) return null;

    const runs: Array<{
      runNumber: number;
      label: string;
      rawKey: string;
      timestamp: string | null;
    }> = [];

    const lastRunKey = Object.keys(selectedRow).find((k) => k.toLowerCase() === 'lastrun') || 'LastRun';
    runs.push({
      runNumber: 1,
      label: 'Run 1 of 8 (Latest Execution)',
      rawKey: lastRunKey,
      timestamp: selectedRow[lastRunKey] ? String(selectedRow[lastRunKey]) : null,
    });

    const has0 = Object.keys(selectedRow).some((k) => k.toLowerCase() === 'previousrun0');
    for (let i = 0; i < 7; i++) {
      const rawTarget = has0 ? `PreviousRun${i}` : `PreviousRun${i + 1}`;
      const foundKey = Object.keys(selectedRow).find((k) => k.toLowerCase() === rawTarget.toLowerCase()) || rawTarget;
      const runNum = i + 2;
      runs.push({
        runNumber: runNum,
        label: `Run ${runNum} of 8`,
        rawKey: foundKey,
        timestamp: selectedRow[foundKey] ? String(selectedRow[foundKey]) : null,
      });
    }

    const runCountVal = selectedRow.RunCount ?? selectedRow.runcount;
    const execNameVal = selectedRow.ExecutableName ?? selectedRow.executablename ?? '';

    return {
      runs,
      runCount: runCountVal !== undefined && runCountVal !== null ? Number(runCountVal) : null,
      execName: String(execNameVal),
      capturedCount: runs.filter((r) => Boolean(r.timestamp)).length,
    };
  })();

  const formatKeyDisplayName = (key: string): string => {
    const k = key.toLowerCase();
    if (k === 'lastrun') return 'LastRun (Run 1 of 8)';
    if (k === 'previousrun0') return 'PreviousRun0 (Run 2 of 8)';
    if (k === 'previousrun1') return 'PreviousRun1 (Run 3 of 8)';
    if (k === 'previousrun2') return 'PreviousRun2 (Run 4 of 8)';
    if (k === 'previousrun3') return 'PreviousRun3 (Run 5 of 8)';
    if (k === 'previousrun4') return 'PreviousRun4 (Run 6 of 8)';
    if (k === 'previousrun5') return 'PreviousRun5 (Run 7 of 8)';
    if (k === 'previousrun6') return 'PreviousRun6 (Run 8 of 8)';
    if (k === 'previousrun7') return 'PreviousRun7 (Run 8 of 8)';
    if (k === 'previousrun8') return 'PreviousRun8 (Run 8 of 8)';
    if (k === 'runcount') return 'Total Run Count';
    return key;
  };

  return (
    <aside
      ref={containerRef}
      style={{ width: width !== undefined ? `${width}px` : undefined }}
      className={`${
        width !== undefined ? '' : 'w-96'
      } bg-white dark:bg-[#1e293b] border-l border-[#cbd5e1] dark:border-[#334155] flex flex-col h-full select-none shrink-0 font-sans shadow-xs overflow-hidden`}
    >
      {/* =========================================================================
          TOP HALF: PREVIEW CARD (Image Preview, OCR Text, Formatted Hex/ASCII Dump)
          ========================================================================= */}
      <div
        style={{ height: `${previewPercent}%` }}
        className="flex flex-col border-b border-[#cbd5e1] dark:border-[#334155] overflow-hidden bg-white dark:bg-[#1e293b] shrink-0"
      >
        {/* Preview Header & Tabs */}
        <div className="h-10 px-3 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <Eye className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
            <span className="font-bold text-xs uppercase tracking-wider text-[#0f172a] dark:text-[#f8fafc]">
              PREVIEW
            </span>
          </div>

          <div className="flex items-center gap-1 bg-white dark:bg-[#1e293b] p-0.5 rounded border border-[#cbd5e1] dark:border-[#334155]">
            <button
              onClick={() => setPreviewTab('hex')}
              className={`px-2 py-0.5 rounded text-[11px] font-semibold transition-colors cursor-pointer ${
                previewTab === 'hex'
                  ? 'bg-[#0284c7] text-white border border-[#0369a1]'
                  : 'text-slate-600 dark:text-slate-400 hover:text-[#0f172a] dark:hover:text-[#f8fafc]'
              }`}
            >
              Hex / Binary
            </button>
            <button
              onClick={() => setPreviewTab('media')}
              className={`px-2 py-0.5 rounded text-[11px] font-semibold transition-colors cursor-pointer ${
                previewTab === 'media'
                  ? 'bg-[#0284c7] text-white border border-[#0369a1]'
                  : 'text-slate-600 dark:text-slate-400 hover:text-[#0f172a] dark:hover:text-[#f8fafc]'
              }`}
              title="Preview Documents, PDFs, Images, and Media files"
            >
              Media / Document
            </button>
            <button
              onClick={() => setPreviewTab('ocr')}
              className={`px-2 py-0.5 rounded text-[11px] font-semibold transition-colors cursor-pointer ${
                previewTab === 'ocr'
                  ? 'bg-[#0284c7] text-white border border-[#0369a1]'
                  : 'text-slate-600 dark:text-slate-400 hover:text-[#0f172a] dark:hover:text-[#f8fafc]'
              }`}
            >
              OCR / Text
            </button>
          </div>
        </div>

        {/* Preview Content Area */}
        <div className="flex-1 overflow-y-auto overflow-x-hidden p-2 text-xs bg-slate-50/40 dark:bg-[#0f172a]/40">
          {previewTab === 'hex' ? (
            // Formatted 16-Byte Hex / ASCII Viewer with Monospace Alignment
            <div className="h-full flex flex-col font-mono text-[11px]">
              {isLoadingHex ? (
                <div className="flex flex-col items-center justify-center h-full text-slate-400 gap-2">
                  <Loader2 className="w-5 h-5 animate-spin text-[#0284c7]" />
                  <span>Reading binary bytes...</span>
                </div>
              ) : hexError ? (
                <div className="p-4 text-center text-slate-400 italic">
                  <Binary className="w-8 h-8 text-slate-300 dark:text-slate-700 mx-auto mb-2" />
                  <p className="font-semibold text-slate-600 dark:text-slate-400">Hex Dump Unavailable</p>
                  <p className="text-[10px] text-slate-400 mt-1">{hexError}</p>
                </div>
              ) : hexData && hexData.lines.length > 0 ? (
                <div className="flex-1 flex flex-col">
                  {/* Hex Navigation Bar */}
                  <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-[#cbd5e1] dark:border-[#334155] text-[10px] text-slate-500">
                    <span className="truncate max-w-[160px]" title={hexData.file_path}>
                      {hexData.file_name} ({hexData.file_size.toLocaleString()} B)
                    </span>
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => setHexOffset((o) => Math.max(0, o - 4096))}
                        disabled={hexOffset === 0}
                        className="p-1 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] hover:bg-slate-50 dark:hover:bg-[#334155] disabled:opacity-30 cursor-pointer"
                        title="Previous 4KB"
                      >
                        <ArrowLeft className="w-3 h-3" />
                      </button>
                      <span className="font-mono px-1">
                        {hexOffset.toString(16).padStart(8, '0').toUpperCase()}
                      </span>
                      <button
                        onClick={() => setHexOffset((o) => o + 4096)}
                        disabled={hexOffset + 4096 >= hexData.file_size}
                        className="p-1 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] hover:bg-slate-50 dark:hover:bg-[#334155] disabled:opacity-30 cursor-pointer"
                        title="Next 4KB"
                      >
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>
                  </div>

                  {/* Hex Lines Scrollable */}
                  <div className="flex-1 overflow-y-auto space-y-0.5 select-text">
                    {hexData.lines.slice(0, 64).map((line) => (
                      <div
                        key={line.offset}
                        className="flex items-center hover:bg-[#bae6fd]/30 dark:hover:bg-[#0c4a6e]/30 rounded px-1"
                      >
                        <span className="text-slate-500 dark:text-slate-400 font-bold w-16 shrink-0 select-none">
                          {line.offset_hex}
                        </span>
                        <span className="text-[#0f172a] dark:text-[#f8fafc] flex-1 px-2 whitespace-nowrap overflow-hidden">
                          {line.hex_bytes}
                        </span>
                        <span className="text-[#0284c7] dark:text-[#38bdf8] w-24 shrink-0 truncate pl-1 border-l border-[#cbd5e1] dark:border-[#334155]">
                          {line.ascii_repr}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="p-4 text-center text-slate-400 italic">
                  <Binary className="w-8 h-8 text-slate-300 dark:text-slate-700 mx-auto mb-2" />
                  <p className="font-semibold text-slate-600 dark:text-slate-400">No Raw File Linked</p>
                  <p className="text-[10px] text-slate-400 mt-1">
                    Select an evidence row that references a staged disk file or executable to render its 16-byte Hex representation.
                  </p>
                </div>
              )}
            </div>
          ) : previewTab === 'media' ? (
            // Media & Document Live Forensic Previewer
            <div className="h-full flex flex-col overflow-hidden">
              {isLoadingContent ? (
                <div className="flex flex-col items-center justify-center h-full text-slate-400 gap-2">
                  <Loader2 className="w-6 h-6 animate-spin text-[#0284c7] dark:text-[#38bdf8]" />
                  <span className="text-xs font-mono">Loading document preview...</span>
                </div>
              ) : fileContent ? (
                <div className="h-full flex flex-col overflow-hidden">
                  {/* Top Document / Media Meta Header */}
                  <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-[#cbd5e1] dark:border-[#334155] text-[10px] text-slate-500 shrink-0">
                    <div className="flex items-center gap-1.5 truncate max-w-[190px]" title={fileContent.file_path}>
                      <FileText className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />
                      <span className="font-bold truncate text-[#0f172a] dark:text-[#f8fafc]">
                        {fileContent.file_name}
                      </span>
                      <span className="text-slate-400 shrink-0">
                        ({fileContent.file_size < 1024 ? `${fileContent.file_size} B` : fileContent.file_size < 1024 * 1024 ? `${(fileContent.file_size / 1024).toFixed(1)} KB` : `${(fileContent.file_size / (1024 * 1024)).toFixed(1)} MB`})
                      </span>
                    </div>

                    <div className="flex items-center gap-1 shrink-0">
                      {fileContent.is_text && fileContent.text_content && (
                        <button
                          onClick={() => handleCopy('doc_text', fileContent.text_content)}
                          className="flex items-center gap-1 px-1.5 py-0.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] hover:bg-slate-50 dark:hover:bg-[#334155] text-slate-700 dark:text-slate-300 font-semibold cursor-pointer"
                          title="Copy document text"
                        >
                          {copiedKey === 'doc_text' ? <Check className="w-3 h-3 text-[#166534]" /> : <Copy className="w-3 h-3 text-slate-500" />}
                          <span>{copiedKey === 'doc_text' ? 'Copied' : 'Copy'}</span>
                        </button>
                      )}
                      <a
                        href={apiClient.getFileRawUrl(caseId, detectedFilePath, false)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1 px-1.5 py-0.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] hover:bg-slate-50 dark:hover:bg-[#334155] text-[#0284c7] dark:text-[#38bdf8] font-semibold cursor-pointer"
                        title="Open in new window"
                      >
                        <ExternalLink className="w-3 h-3" />
                        <span>Open</span>
                      </a>
                      <a
                        href={apiClient.getFileRawUrl(caseId, detectedFilePath, true)}
                        download={fileContent.file_name}
                        className="p-1 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] hover:bg-slate-50 dark:hover:bg-[#334155] text-slate-600 dark:text-slate-400 cursor-pointer"
                        title="Download raw file"
                      >
                        <Download className="w-3 h-3" />
                      </a>
                    </div>
                  </div>

                  {/* Document / Media Body */}
                  <div className="flex-1 overflow-auto rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b]">
                    {fileContent.is_text && fileContent.text_content ? (
                      <pre className="p-3 font-mono text-[11px] whitespace-pre-wrap leading-relaxed select-text text-[#0f172a] dark:text-[#f8fafc]">
                        {fileContent.text_content}
                      </pre>
                    ) : fileContent.is_pdf ? (
                      <iframe
                        src={`${apiClient.getFileRawUrl(caseId, detectedFilePath, false)}#view=FitH`}
                        title={fileContent.file_name}
                        className="w-full h-full border-0"
                      />
                    ) : fileContent.is_image ? (
                      <div className="w-full h-full flex items-center justify-center p-2 bg-slate-50 dark:bg-[#0f172a]">
                        <img
                          src={apiClient.getFileRawUrl(caseId, detectedFilePath, false)}
                          alt={fileContent.file_name}
                          className="max-h-full max-w-full object-contain rounded shadow-2xs"
                        />
                      </div>
                    ) : fileContent.is_media && fileContent.mime_type.startsWith('video') ? (
                      <div className="w-full h-full flex items-center justify-center p-2 bg-black">
                        <video controls className="max-h-full max-w-full rounded">
                          <source src={apiClient.getFileRawUrl(caseId, detectedFilePath, false)} type={fileContent.mime_type} />
                          Your browser does not support the video tag.
                        </video>
                      </div>
                    ) : fileContent.is_media && fileContent.mime_type.startsWith('audio') ? (
                      <div className="w-full h-full flex flex-col items-center justify-center p-4">
                        <audio controls className="w-full">
                          <source src={apiClient.getFileRawUrl(caseId, detectedFilePath, false)} type={fileContent.mime_type} />
                          Your browser does not support the audio tag.
                        </audio>
                      </div>
                    ) : (
                      // Structured file metadata card for binary files
                      <div className="p-6 text-center text-slate-500">
                        <FileText className="w-10 h-10 text-slate-400 mx-auto mb-2" />
                        <p className="font-bold text-xs text-[#0f172a] dark:text-[#f8fafc]">{fileContent.file_name}</p>
                        <p className="text-[11px] text-slate-400 mt-1">Binary file ({fileContent.mime_type})</p>
                        <p className="text-[11px] text-slate-400">{fileContent.file_size.toLocaleString()} bytes</p>
                        <button
                          onClick={() => setPreviewTab('hex')}
                          className="mt-3 px-3 py-1.5 rounded bg-[#0284c7] hover:bg-[#0369a1] text-white font-semibold text-xs border border-[#0369a1] cursor-pointer inline-flex items-center gap-1.5"
                        >
                          <Binary className="w-3.5 h-3.5" />
                          <span>View in Hex / Binary Inspector</span>
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="p-6 text-center text-slate-400 italic">
                  <FileText className="w-8 h-8 text-slate-300 dark:text-slate-700 mx-auto mb-2" />
                  <p className="font-semibold text-slate-600 dark:text-slate-400">Document Preview Unavailable</p>
                  <p className="text-[10px] text-slate-400 mt-1">
                    {contentError || 'Select a document, image, or text evidence file to render its preview.'}
                  </p>
                  {detectedFilePath && (
                    <button
                      onClick={() => setPreviewTab('hex')}
                      className="mt-3 px-2.5 py-1 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] hover:bg-slate-50 dark:hover:bg-[#334155] text-xs font-semibold text-[#0284c7] dark:text-[#38bdf8] cursor-pointer inline-flex items-center gap-1.5"
                    >
                      <Binary className="w-3 h-3" />
                      <span>Try Hex / Binary Inspector</span>
                    </button>
                  )}
                </div>
              )}
            </div>
          ) : (
            // OCR / Extracted Text Preview
            <div className="h-full flex flex-col">
              <div className="flex items-center justify-between pb-1 mb-2 border-b border-[#cbd5e1] dark:border-[#334155] text-[10px] text-slate-500">
                <span className="font-bold uppercase tracking-wider">RapidOCR Extracted Text</span>
                {ocrText && (
                  <button
                    onClick={() => handleCopy('ocr_text', ocrText)}
                    className="flex items-center gap-1 text-[#0284c7] dark:text-[#38bdf8] hover:underline font-semibold cursor-pointer"
                  >
                    <Copy className="w-3 h-3" />
                    <span>Copy Text</span>
                  </button>
                )}
              </div>
              {ocrText ? (
                <div className="flex-1 overflow-y-auto p-2 bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded whitespace-pre-wrap font-sans text-xs text-[#0f172a] dark:text-[#f8fafc] leading-relaxed select-text">
                  {ocrText}
                </div>
              ) : (
                <div className="p-6 text-center text-slate-400 italic">
                  <p className="font-semibold text-slate-600 dark:text-slate-400">No Extracted Text</p>
                  <p className="text-[10px] text-slate-400 mt-1">
                    This evidence item does not have OCR extracted text.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* DRAGGABLE HORIZONTAL SPLITTER (Between Preview and Details) */}
      <ResizeHandle
        orientation="horizontal"
        onMouseDown={handleVerticalMouseDown}
        onDoubleClick={resetVerticalPercent}
        isDragging={isDraggingVertical}
        title="Drag to resize Preview vs Details height (double-click to reset)"
      />

      {/* =========================================================================
          BOTTOM HALF: DETAILS CARD (Artifact Information + Evidence Information)
          ========================================================================= */}
      <div className="flex-1 flex flex-col overflow-hidden bg-white dark:bg-[#1e293b]">
        {/* Details Header & Bookmark Button */}
        <div className="h-10 px-3 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <FileText className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
            <span className="font-bold text-xs uppercase tracking-wider text-[#0f172a] dark:text-[#f8fafc]">
              DETAILS
            </span>
          </div>

          <button
            onClick={() => setIsBookmarking(!isBookmarking)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] text-[#0f172a] dark:text-[#f8fafc] border border-[#cbd5e1] dark:border-[#334155] font-semibold text-[11px] shadow-2xs transition-colors cursor-pointer"
            title="Add forensic tag / bookmark"
          >
            <Bookmark className="w-3 h-3 text-[#0284c7] dark:text-[#38bdf8]" />
            <span>+ Bookmark</span>
          </button>
        </div>

        {/* Inline Bookmark Creator if open */}
        {isBookmarking && (
          <div className="p-3 bg-[#f8fafc] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex flex-col gap-2 shrink-0 animate-in fade-in duration-100">
            <div className="flex items-center justify-between">
              <span className="font-bold text-xs text-[#0f172a] dark:text-[#f8fafc]">
                Tag Evidence Item
              </span>
              <button onClick={() => setIsBookmarking(false)} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer">
                ✕
              </button>
            </div>
            <select
              value={selectedTag}
              onChange={(e) => setSelectedTag(e.target.value)}
              className="bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded p-1 text-xs font-semibold text-[#0f172a] dark:text-[#f8fafc]"
            >
              <option value="Key Evidence">Key Evidence</option>
              <option value="Malware">Malware</option>
              <option value="Initial Access">Initial Access</option>
              <option value="Persistence">Persistence</option>
              <option value="Lateral Movement">Lateral Movement</option>
              <option value="Exfiltration">Exfiltration</option>
            </select>
            <input
              type="text"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Examiner findings / notes..."
              className="bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded px-2 py-1 text-xs text-[#0f172a] dark:text-[#f8fafc]"
            />
            <button
              onClick={handleCreateBookmark}
              className="py-1 rounded bg-[#0284c7] hover:bg-[#0369a1] text-white font-bold text-xs border border-[#0369a1] cursor-pointer"
            >
              Save Bookmark
            </button>
          </div>
        )}

        {bookmarkSuccess && (
          <div className="p-2 badge-status-success text-xs text-center flex items-center justify-center gap-1">
            <Check className="w-3.5 h-3.5" /> Bookmark Saved!
          </div>
        )}

        {/* Two-Column Key-Value Collapsible Sections */}
        <div className="flex-1 overflow-y-auto p-3 space-y-3 select-text bg-white dark:bg-[#1e293b]">
          {!selectedRow ? (
            <div className="p-8 text-center text-slate-400 italic text-xs">
              <Info className="w-8 h-8 text-slate-300 dark:text-slate-700 mx-auto mb-2" />
              <p className="font-semibold text-slate-600 dark:text-slate-400">No Evidence Item Selected</p>
              <p className="text-[11px] text-slate-400 mt-1">
                Click any row in the center Evidence table to inspect detailed attributes and raw binary hex/media preview.
              </p>
            </div>
          ) : (
            <>
              {/* Section: PREFETCH EXECUTION TIMESTAMPS (All 8 Runs) */}
              {prefetchRuns && (
                <div className="border border-sky-300 dark:border-sky-800 rounded overflow-hidden bg-sky-50/30 dark:bg-sky-950/20 shadow-2xs">
                  <button
                    onClick={() => setIsPrefetchHistoryOpen(!isPrefetchHistoryOpen)}
                    className="w-full px-3 py-2 bg-sky-100/70 dark:bg-sky-900/40 flex items-center justify-between text-left font-bold text-[11px] uppercase tracking-wider text-sky-900 dark:text-sky-100 border-b border-sky-200 dark:border-sky-800 cursor-pointer"
                  >
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />
                      <span>PREFETCH RUNS (ALL 8 RUNS)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {prefetchRuns.runCount !== null && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-sky-200/80 dark:bg-sky-800/80 text-sky-800 dark:text-sky-200">
                          Total: {prefetchRuns.runCount}
                        </span>
                      )}
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-100 dark:bg-emerald-900/60 text-emerald-800 dark:text-emerald-200">
                        {prefetchRuns.capturedCount}/8 Recorded
                      </span>
                      {isPrefetchHistoryOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                    </div>
                  </button>

                  {isPrefetchHistoryOpen && (
                    <div className="p-2 space-y-1.5">
                      <div className="text-[10px] text-slate-500 dark:text-slate-400 px-1 pb-1 border-b border-sky-200/50 dark:border-sky-800/50 flex items-center justify-between">
                        <span>Target: <strong className="font-mono text-slate-700 dark:text-slate-200">{prefetchRuns.execName || 'Unknown'}</strong></span>
                        <span>Max 8 Runs (Windows 8+)</span>
                      </div>

                      <div className="space-y-1">
                        {prefetchRuns.runs.map((run) => (
                          <div
                            key={run.runNumber}
                            className={`flex items-center justify-between p-1.5 rounded text-xs transition-colors ${
                              run.timestamp
                                ? run.runNumber === 1
                                  ? 'bg-sky-100/60 dark:bg-sky-900/30 border border-sky-300 dark:border-sky-700 font-semibold'
                                  : 'bg-white dark:bg-[#1e293b] border border-slate-200 dark:border-slate-700'
                                : 'bg-slate-50/50 dark:bg-slate-900/30 border border-dashed border-slate-200 dark:border-slate-800 opacity-60'
                            }`}
                          >
                            <div className="flex items-center gap-1.5 min-w-0">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold shrink-0 ${
                                  run.timestamp
                                    ? run.runNumber === 1
                                      ? 'bg-sky-600 text-white'
                                      : 'bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-200'
                                    : 'bg-slate-100 dark:bg-slate-800 text-slate-400'
                                }`}
                              >
                                #{run.runNumber}
                              </span>
                              <div className="flex flex-col min-w-0">
                                <span className="text-[11px] font-medium text-slate-700 dark:text-slate-300 truncate">
                                  {run.label}
                                </span>
                                <span className="text-[9px] font-mono text-slate-400 truncate">
                                  Column: {run.rawKey}
                                </span>
                              </div>
                            </div>

                            <div className="flex items-center gap-1.5 min-w-0 justify-end">
                              {run.timestamp ? (
                                <>
                                  <span className="font-mono text-[11px] text-slate-900 dark:text-slate-100 select-all truncate">
                                    {run.timestamp}
                                  </span>
                                  <button
                                    onClick={() => handleCopy(`prefetch_run_${run.runNumber}`, run.timestamp)}
                                    className="p-1 rounded hover:bg-sky-200/50 dark:hover:bg-sky-800 text-slate-500 shrink-0 cursor-pointer"
                                    title={`Copy Run #${run.runNumber} timestamp`}
                                  >
                                    {copiedKey === `prefetch_run_${run.runNumber}` ? (
                                      <Check className="w-3 h-3 text-[#166534]" />
                                    ) : (
                                      <Copy className="w-3 h-3" />
                                    )}
                                  </button>
                                </>
                              ) : (
                                <span className="text-[10px] italic text-slate-400">
                                  Not recorded (no timestamp)
                                </span>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>

                      <div className="p-1.5 rounded bg-slate-100/70 dark:bg-slate-800/50 text-[10px] text-slate-500 dark:text-slate-400 leading-tight">
                        ℹ️ Windows 8, 10, and 11 Prefetch structures maintain up to 8 execution run times (1 latest + 7 historical). Windows XP, Vista, and 7 store 1 timestamp.
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Section 1: ARTIFACT INFORMATION */}
              <div className="border border-[#cbd5e1] dark:border-[#334155] rounded overflow-hidden bg-white dark:bg-[#1e293b]">
                <button
                  onClick={() => setIsArtifactInfoOpen(!isArtifactInfoOpen)}
                  className="w-full px-3 py-1.5 bg-[#f8fafc] dark:bg-[#0f172a] flex items-center justify-between text-left font-bold text-[11px] uppercase tracking-wider text-[#0f172a] dark:text-[#f8fafc] border-b border-[#cbd5e1] dark:border-[#334155] cursor-pointer"
                >
                  <div className="flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
                    <span>ARTIFACT INFORMATION</span>
                  </div>
                  {isArtifactInfoOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                </button>

                {isArtifactInfoOpen && (
                  <div className="p-2 space-y-1 divide-y divide-[#e2e8f0] dark:divide-[#334155]">
                    <div className="flex items-center justify-between py-1 px-1 text-xs">
                      <span className="font-semibold text-slate-500">Table Name</span>
                      <span className="font-mono text-[#0f172a] dark:text-[#f8fafc]">{tableName || 'raw_data'}</span>
                    </div>
                    <div className="flex items-center justify-between py-1 px-1 text-xs">
                      <span className="font-semibold text-slate-500">Row ID</span>
                      <span className="font-mono font-bold text-[#0284c7] dark:text-[#38bdf8]">#{String(selectedRow._row_id ?? '')}</span>
                    </div>

                    {artifactInfoKeys
                      .filter((k) => k !== '_row_id')
                      .map((key) => {
                        const val = selectedRow[key];
                        const strVal = String(val ?? '');

                        return (
                          <div key={key} className="flex items-start justify-between py-1 px-1 text-xs group">
                            <span className="font-semibold text-slate-500 max-w-[140px] truncate shrink-0" title={key}>
                              {formatKeyDisplayName(key)}
                            </span>
                            <div className="flex items-center gap-1.5 max-w-[210px] min-w-0 justify-end">
                              <span
                                className="font-mono text-[#0f172a] dark:text-[#f8fafc] truncate select-all"
                                title={strVal}
                              >
                                {strVal || <span className="italic text-slate-400">—</span>}
                              </span>

                              <button
                                onClick={() => handleCopy(key, strVal)}
                                className="p-0.5 rounded opacity-0 group-hover:opacity-100 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 shrink-0 cursor-pointer"
                                title="Copy value"
                              >
                                {copiedKey === key ? <Check className="w-3 h-3 text-[#166534]" /> : <Copy className="w-3 h-3" />}
                              </button>
                            </div>
                          </div>
                        );
                      })}
                  </div>
                )}
              </div>

              {/* Section 2: EVIDENCE INFORMATION */}
              <div className="border border-[#cbd5e1] dark:border-[#334155] rounded overflow-hidden bg-white dark:bg-[#1e293b]">
                <button
                  onClick={() => setIsEvidenceInfoOpen(!isEvidenceInfoOpen)}
                  className="w-full px-3 py-1.5 bg-[#f8fafc] dark:bg-[#0f172a] flex items-center justify-between text-left font-bold text-[11px] uppercase tracking-wider text-[#0f172a] dark:text-[#f8fafc] border-b border-[#cbd5e1] dark:border-[#334155] cursor-pointer"
                >
                  <div className="flex items-center gap-1.5">
                    <HardDrive className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
                    <span>EVIDENCE INFORMATION</span>
                  </div>
                  {isEvidenceInfoOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                </button>

                {isEvidenceInfoOpen && (
                  <div className="p-2 space-y-1 divide-y divide-[#e2e8f0] dark:divide-[#334155]">
                    {evidenceInfoKeys.length === 0 ? (
                      <div className="p-2 text-slate-400 italic text-xs">No additional attributes.</div>
                    ) : (
                      evidenceInfoKeys.map((key) => {
                        const val = selectedRow[key];
                        const strVal = String(val ?? '');

                        return (
                          <div key={key} className="flex items-start justify-between py-1 px-1 text-xs group">
                            <span className="font-semibold text-slate-500 max-w-[140px] truncate shrink-0" title={key}>
                              {formatKeyDisplayName(key)}
                            </span>

                            <div className="flex items-center gap-1.5 max-w-[210px] min-w-0 justify-end">
                              <span
                                className="font-mono text-[#0f172a] dark:text-[#f8fafc] truncate select-all"
                                title={strVal}
                              >
                                {strVal || <span className="italic text-slate-400">—</span>}
                              </span>

                              <button
                                onClick={() => handleCopy(key, strVal)}
                                className="p-0.5 rounded opacity-0 group-hover:opacity-100 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 shrink-0 cursor-pointer"
                                title="Copy value"
                              >
                                {copiedKey === key ? <Check className="w-3 h-3 text-[#166534]" /> : <Copy className="w-3 h-3" />}
                              </button>
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </aside>
  );
};