import React, { useState, useEffect, useRef } from 'react';
import {
  Search,
  Upload,
  Plus,
  Trash2,
  X,
  FileText,
  AlertCircle,
  CheckCircle2,
  RefreshCw,
  Hash,
  FileSpreadsheet,
  Loader2,
  Filter
} from 'lucide-react';
import { apiClient, CaseKeyword } from '../api/client';

interface KeywordManagerProps {
  caseId: string;
  isOpen?: boolean;
  onClose?: () => void;
  isModal?: boolean;
  onKeywordsUpdated?: () => void;
  selectedKeywordFilters?: string[];
  onToggleKeywordFilter?: (keyword: string) => void;
}

export const KeywordManager: React.FC<KeywordManagerProps> = ({
  caseId,
  isOpen = true,
  onClose,
  isModal = true,
  onKeywordsUpdated,
  selectedKeywordFilters = [],
  onToggleKeywordFilter,
}) => {
  const [keywords, setKeywords] = useState<CaseKeyword[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Manual Add Form State
  const [newKeyword, setNewKeyword] = useState<string>('');
  const [isRegex, setIsRegex] = useState<boolean>(false);
  const [isAdding, setIsAdding] = useState<boolean>(false);

  // Search filter for keywords table
  const [tableSearch, setTableSearch] = useState<string>('');
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Fetch keywords for the case
  const loadKeywords = async () => {
    if (!caseId) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await apiClient.listKeywords(caseId);
      setKeywords(res.keywords || []);
    } catch (err) {
      console.warn('Failed to load keywords:', err);
      setKeywords([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (caseId && isOpen) {
      loadKeywords();
    }
  }, [caseId, isOpen]);

  // Handle Manual Add
  const handleAddKeyword = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleanKw = newKeyword.trim();
    if (!cleanKw || !caseId) return;

    setIsAdding(true);
    setError(null);
    setSuccessMessage(null);
    try {
      const res = await apiClient.addKeywords(caseId, {
        keywords: [cleanKw],
        source_file: 'Manual',
        is_regex: isRegex,
      });
      setKeywords(res.keywords || []);
      setNewKeyword('');
      setSuccessMessage(`Added keyword "${cleanKw}" successfully.`);
      if (onKeywordsUpdated) onKeywordsUpdated();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsAdding(false);
    }
  };

  // Handle File Upload
  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files || files.length === 0 || !caseId) return;

    const file = files[0];
    setIsUploading(true);
    setError(null);
    setSuccessMessage(null);

    try {
      const res = await apiClient.uploadKeywordsFile(caseId, file);
      setKeywords(res.keywords || []);
      setSuccessMessage(`Uploaded keywords from ${file.name} successfully.`);
      if (onKeywordsUpdated) onKeywordsUpdated();
      setTimeout(() => setSuccessMessage(null), 3500);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsUploading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  // Handle Delete Specific Keyword
  const handleDeleteKeyword = async (keywordId: string, kwText: string) => {
    if (!caseId || !keywordId) return;
    setDeletingId(keywordId);
    setError(null);
    try {
      await apiClient.deleteKeyword(caseId, keywordId);
      setKeywords((prev) => prev.filter((k) => k.keyword_id !== keywordId));
      setSuccessMessage(`Removed keyword "${kwText}".`);
      if (onKeywordsUpdated) onKeywordsUpdated();
      setTimeout(() => setSuccessMessage(null), 2500);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setDeletingId(null);
    }
  };

  // Filtered keywords for table
  const filteredKeywords = keywords.filter((k) => {
    if (!tableSearch.trim()) return true;
    const q = tableSearch.toLowerCase();
    return (
      k.keyword.toLowerCase().includes(q) ||
      (k.source_file && k.source_file.toLowerCase().includes(q))
    );
  });

  const totalHits = keywords.reduce((sum, k) => sum + k.hit_count, 0);

  const content = (
    <div className="flex flex-col h-full font-sans text-xs text-[#0f172a] dark:text-[#f8fafc] bg-white dark:bg-[#1e293b]">
      {/* Notifications / Errors */}
      {error && (
        <div className="mx-4 mt-3 p-2.5 rounded badge-status-error text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-[#991b1b]" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="p-0.5 hover:opacity-80 cursor-pointer">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {successMessage && (
        <div className="mx-4 mt-3 p-2.5 rounded badge-status-success text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0 text-[#166534]" />
          <span>{successMessage}</span>
        </div>
      )}

      {/* Top Input & Upload Controls Card */}
      <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4 border-b border-[#cbd5e1] dark:border-[#334155] bg-[#f1f5f9] dark:bg-[#0f172a] shrink-0">
        {/* Option 1: File Upload */}
        <div className="p-3.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] shadow-2xs flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 font-bold text-[#0f172a] dark:text-[#f8fafc] mb-1">
              <Upload className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
              <span className="text-sm">Import Keyword List</span>
            </div>
            <p className="text-[11.5px] text-slate-500 dark:text-slate-400 mb-3">
              Upload a newline-separated <code>.txt</code> or comma-separated <code>.csv</code> keyword/IOC file.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              accept=".txt,.csv"
              className="hidden"
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={isUploading}
              className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#334155] text-[#0f172a] dark:text-[#f8fafc] border border-[#cbd5e1] dark:border-[#334155] font-semibold text-xs shadow-2xs transition-colors disabled:opacity-50 cursor-pointer"
            >
              {isUploading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-[#0284c7]" />
                  <span>Uploading & Scanning Case...</span>
                </>
              ) : (
                <>
                  <FileSpreadsheet className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
                  <span>Choose .txt or .csv File...</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Option 2: Manual Add */}
        <div className="p-3.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] shadow-2xs flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 font-bold text-[#0f172a] dark:text-[#f8fafc] mb-1">
              <Plus className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
              <span className="text-sm">Add Specific Keyword</span>
            </div>
            <p className="text-[11.5px] text-slate-500 dark:text-slate-400 mb-2">
              Add individual IOC string or regular expression pattern.
            </p>
          </div>

          <form onSubmit={handleAddKeyword} className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={newKeyword}
                onChange={(e) => setNewKeyword(e.target.value)}
                placeholder="e.g. mimikatz, evil.exe, powershell -enc..."
                className="flex-1 bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] focus:border-[#0284c7] rounded px-2.5 py-1.5 text-xs text-[#0f172a] dark:text-[#f8fafc] placeholder-slate-400 focus:outline-none font-mono"
              />
              <button
                type="submit"
                disabled={!newKeyword.trim() || isAdding}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-[#0284c7] hover:bg-[#0369a1] text-white font-semibold text-xs border border-[#0369a1] shadow-2xs transition-colors disabled:opacity-50 shrink-0 cursor-pointer"
              >
                {isAdding ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                <span>Add Keyword</span>
              </button>
            </div>

            <label className="flex items-center gap-2 cursor-pointer select-none text-[11px] text-slate-600 dark:text-slate-400">
              <input
                type="checkbox"
                checked={isRegex}
                onChange={(e) => setIsRegex(e.target.checked)}
                className="w-3.5 h-3.5 rounded border-[#cbd5e1] text-[#0284c7] focus:ring-0 cursor-pointer"
              />
              <span>Treat as Regular Expression (Regex Pattern)</span>
            </label>
          </form>
        </div>
      </div>

      {/* Keywords Table Header & Search Filter */}
      <div className="px-4 py-2.5 bg-white dark:bg-[#1e293b] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-2">
          <Hash className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
          <span className="font-bold text-xs uppercase tracking-wider text-[#0f172a] dark:text-[#f8fafc]">
            Keyword List ({keywords.length} Defined, {totalHits.toLocaleString()} Hits)
          </span>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative w-52">
            <Search className="w-3 h-3 absolute left-2.5 top-2 text-slate-400 pointer-events-none" />
            <input
              type="text"
              value={tableSearch}
              onChange={(e) => setTableSearch(e.target.value)}
              placeholder="Filter list..."
              className="w-full bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] focus:border-[#0284c7] rounded pl-7 pr-6 py-1 text-xs text-[#0f172a] dark:text-[#f8fafc] placeholder-slate-400 focus:outline-none"
            />
            {tableSearch && (
              <button
                onClick={() => setTableSearch('')}
                className="absolute right-2 top-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
              >
                ✕
              </button>
            )}
          </div>

          <button
            onClick={loadKeywords}
            disabled={isLoading}
            className="p-1.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#334155] text-slate-600 dark:text-slate-300 transition-colors cursor-pointer"
            title="Refresh Hit Counts"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-[#0284c7]' : ''}`} />
          </button>
        </div>
      </div>

      {/* Scrollable Keyword Table */}
      <div className="flex-1 overflow-y-auto p-4 bg-[#f8fafc] dark:bg-[#0f172a]">
        {isLoading && keywords.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-slate-400 gap-2">
            <Loader2 className="w-6 h-6 animate-spin text-[#0284c7]" />
            <span>Loading keywords...</span>
          </div>
        ) : filteredKeywords.length === 0 ? (
          <div className="p-8 text-center text-slate-500 border border-dashed border-[#cbd5e1] dark:border-[#334155] rounded">
            {tableSearch ? (
              <p>No keywords match "{tableSearch}".</p>
            ) : (
              <div>
                <FileText className="w-8 h-8 text-slate-400 mx-auto mb-2" />
                <p className="font-semibold text-slate-600 dark:text-slate-400 mb-1">
                  No keyword lists configured for this case yet.
                </p>
                <p className="text-[11px] text-slate-400">
                  Upload a list of keywords/hashes/IOCs or add them individually above.
                </p>
              </div>
            )}
          </div>
        ) : (
          <div className="border border-[#cbd5e1] dark:border-[#334155] rounded overflow-hidden shadow-2xs bg-white dark:bg-[#1e293b]">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] text-[11px] uppercase tracking-wider text-slate-600 dark:text-slate-400 font-semibold font-mono">
                  <th className="py-2.5 px-3">Keyword / Pattern</th>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Source List</th>
                  <th className="py-2.5 px-3 text-right">Hit Count</th>
                  {onToggleKeywordFilter && <th className="py-2.5 px-3 text-center">Filter</th>}
                  <th className="py-2.5 px-3 text-center w-16">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#e2e8f0] dark:divide-[#334155] font-mono text-[11.5px]">
                {filteredKeywords.map((kw) => {
                  const isFiltered = selectedKeywordFilters.includes(kw.keyword);
                  const isDeleting = deletingId === kw.keyword_id;

                  return (
                    <tr
                      key={kw.keyword_id}
                      className="hover:bg-slate-50 dark:hover:bg-[#334155]/40 transition-colors"
                    >
                      <td className="py-2.5 px-3 font-semibold text-[#0f172a] dark:text-[#f8fafc] max-w-xs truncate">
                        <span title={kw.keyword}>{kw.keyword}</span>
                      </td>

                      <td className="py-2.5 px-3">
                        <span className="text-[10px] font-sans px-2 py-0.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#0f172a] text-slate-700 dark:text-slate-300 font-semibold">
                          {kw.is_regex ? 'Regex' : 'Exact String'}
                        </span>
                      </td>

                      <td className="py-2.5 px-3 font-sans text-slate-500 dark:text-slate-400 text-xs">
                        {kw.source_file || 'Manual'}
                      </td>

                      <td className="py-2.5 px-3 text-right">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                            kw.hit_count > 0
                              ? 'badge-status-success'
                              : 'bg-slate-100 dark:bg-[#0f172a] text-slate-500 border border-[#cbd5e1] dark:border-[#334155]'
                          }`}
                        >
                          {kw.hit_count.toLocaleString()} hits
                        </span>
                      </td>

                      {onToggleKeywordFilter && (
                        <td className="py-2.5 px-3 text-center font-sans">
                          <button
                            onClick={() => onToggleKeywordFilter(kw.keyword)}
                            className={`p-1 rounded text-xs transition-colors cursor-pointer border ${
                              isFiltered
                                ? 'bg-[#0284c7] text-white border-[#0369a1] font-bold'
                                : 'bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#334155] border-[#cbd5e1] dark:border-[#334155] text-slate-600 dark:text-slate-300'
                            }`}
                            title={isFiltered ? 'Active filter' : 'Filter by this keyword'}
                          >
                            <Filter className="w-3 h-3" />
                          </button>
                        </td>
                      )}

                      <td className="py-2.5 px-3 text-center">
                        <button
                          onClick={() => handleDeleteKeyword(kw.keyword_id, kw.keyword)}
                          disabled={isDeleting}
                          className="p-1 rounded text-[#991b1b] dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/50 transition-colors cursor-pointer"
                          title="Delete keyword"
                        >
                          {isDeleting ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <Trash2 className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );

  if (!isModal) {
    return content;
  }

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-4xl max-h-[85vh] bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150 text-[#0f172a] dark:text-[#f8fafc]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Top Header */}
        <div className="h-14 px-5 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] text-[#0284c7] dark:text-[#38bdf8]">
              <Hash className="w-5 h-5" />
            </div>
            <div>
              <h2 className="font-bold text-sm text-[#0f172a] dark:text-[#f8fafc] tracking-wide uppercase">
                WFT Keyword Lists Manager
              </h2>
              <span className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                Case: {caseId}
              </span>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded hover:bg-slate-200 dark:hover:bg-[#334155] text-slate-500 hover:text-[#0f172a] dark:hover:text-white transition-colors cursor-pointer"
            title="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-hidden flex flex-col">{content}</div>

        {/* Modal Footer */}
        <div className="px-5 py-3 bg-[#f1f5f9] dark:bg-[#0f172a] border-t border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0">
          <span className="text-[11px] text-slate-500 dark:text-slate-400">
            Keywords are continuously indexed against evidence across all artifact tables.
          </span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc] font-semibold text-xs transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
