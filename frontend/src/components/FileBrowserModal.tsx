import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Folder,
  FolderOpen,
  HardDrive,
  File,
  Disc,
  FileArchive,
  ArrowUp,
  RefreshCw,
  Search,
  Check,
  X,
  Home,
  Download,
  FileText,
  Monitor,
  AlertTriangle,
  Loader2,
} from 'lucide-react';
import {
  apiClient,
  ListDirectoryResponse,
  DirectoryEntry,
  DriveInfo,
  QuickAccessItem,
} from '../api/client';

export interface FileBrowserModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelect: (selectedPath: string) => void;
  mode: 'file' | 'folder';
  title?: string;
  initialPath?: string;
}

export const FileBrowserModal: React.FC<FileBrowserModalProps> = ({
  isOpen,
  onClose,
  onSelect,
  mode,
  title,
  initialPath,
}) => {
  const [currentPath, setCurrentPath] = useState<string>('');
  const [parentPath, setParentPath] = useState<string | null>(null);
  const [drives, setDrives] = useState<DriveInfo[]>([]);
  const [quickAccess, setQuickAccess] = useState<QuickAccessItem[]>([]);
  const [entries, setEntries] = useState<DirectoryEntry[]>([]);
  const [selectedItemPath, setSelectedItemPath] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Address bar input state
  const [addressInput, setAddressInput] = useState<string>('');
  // Filter search inside directory
  const [searchTerm, setSearchTerm] = useState<string>('');
  // Filter images only vs all files (for file mode)
  const [showImagesOnly, setShowImagesOnly] = useState<boolean>(true);

  // Load directory contents
  const loadDirectory = useCallback(async (path?: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const data: ListDirectoryResponse = await apiClient.listDirectory(path);
      setCurrentPath(data.current_path || '');
      setAddressInput(data.current_path || '');
      setParentPath(data.parent_path ?? null);
      setDrives(data.drives || []);
      setQuickAccess(data.quick_access || []);
      setEntries(data.entries || []);
      if (data.error) {
        setError(data.error);
      }
      if (mode === 'folder' && data.current_path) {
        setSelectedItemPath(data.current_path);
      } else {
        setSelectedItemPath('');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(`Failed to read path: ${msg}`);
    } finally {
      setIsLoading(false);
    }
  }, [mode]);

  // Initial load when modal opens
  useEffect(() => {
    if (isOpen) {
      loadDirectory(initialPath || '');
    }
  }, [isOpen, initialPath, loadDirectory]);

  // Handle navigate to parent folder
  const handleNavigateUp = () => {
    if (parentPath !== null) {
      loadDirectory(parentPath);
    }
  };

  // Handle manual address submission
  const handleAddressSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (addressInput.trim()) {
      loadDirectory(addressInput.trim());
    }
  };

  // Handle item click (selection)
  const handleItemClick = (entry: DirectoryEntry) => {
    setSelectedItemPath(entry.path);
  };

  // Handle item double-click (navigation)
  const handleItemDoubleClick = (entry: DirectoryEntry) => {
    if (entry.is_dir || entry.is_drive) {
      loadDirectory(entry.path);
    } else if (mode === 'file') {
      onSelect(entry.path);
      onClose();
    }
  };

  // Handle confirm selection
  const handleConfirm = () => {
    if (selectedItemPath) {
      onSelect(selectedItemPath);
      onClose();
    } else if (mode === 'folder' && currentPath) {
      onSelect(currentPath);
      onClose();
    }
  };

  // Filter entries
  const filteredEntries = useMemo(() => {
    return entries.filter((e) => {
      if (searchTerm.trim()) {
        const q = searchTerm.toLowerCase();
        if (!e.name.toLowerCase().includes(q)) return false;
      }
      if (mode === 'file' && showImagesOnly && !e.is_dir && !e.is_drive) {
        return e.is_image || e.is_archive;
      }
      return true;
    });
  }, [entries, searchTerm, mode, showImagesOnly]);

  if (!isOpen) return null;

  const modalTitle =
    title || (mode === 'file' ? 'Select Forensic Disk Image' : 'Select Target Directory');

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 select-none animate-in fade-in duration-150">
      <div className="bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded shadow-2xl w-full max-w-4xl h-[720px] max-h-[92vh] flex flex-col overflow-hidden text-[#0f172a] dark:text-[#f8fafc] font-sans">
        {/* Header */}
        <div className="h-12 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] px-4 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            {mode === 'file' ? (
              <Disc className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
            ) : (
              <FolderOpen className="w-4 h-4 text-[#0284c7] dark:text-[#38bdf8]" />
            )}
            <span className="font-bold text-sm tracking-wide">
              {modalTitle}
            </span>
            <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] text-[#0284c7] dark:text-[#38bdf8] font-bold">
              {mode === 'file' ? 'Disk Image Mode' : 'Folder Mode'}
            </span>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1 hover:bg-slate-200 dark:hover:bg-[#334155] rounded text-slate-500 hover:text-[#0f172a] dark:hover:text-white transition-colors cursor-pointer"
            title="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Address & Navigation Bar */}
        <div className="p-2.5 bg-white dark:bg-[#1e293b] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={handleNavigateUp}
            disabled={parentPath === null || isLoading}
            className="p-1.5 bg-white dark:bg-[#0f172a] hover:bg-slate-50 dark:hover:bg-[#334155] disabled:opacity-40 rounded border border-[#cbd5e1] dark:border-[#334155] text-slate-700 dark:text-slate-300 transition-colors cursor-pointer shrink-0"
            title="Go up to parent directory"
          >
            <ArrowUp className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={() => loadDirectory(currentPath)}
            disabled={isLoading}
            className="p-1.5 bg-white dark:bg-[#0f172a] hover:bg-slate-50 dark:hover:bg-[#334155] disabled:opacity-40 rounded border border-[#cbd5e1] dark:border-[#334155] text-slate-700 dark:text-slate-300 transition-colors cursor-pointer shrink-0"
            title="Refresh current directory"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-[#0284c7]' : ''}`} />
          </button>

          <form onSubmit={handleAddressSubmit} className="flex-1 flex items-center gap-1.5">
            <div className="relative flex-1">
              <input
                type="text"
                value={addressInput}
                onChange={(e) => setAddressInput(e.target.value)}
                placeholder="Type or paste Windows path (e.g. C:\Forensics or D:\Evidence)"
                className="w-full bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] focus:border-[#0284c7] rounded px-3 py-1.5 text-xs text-[#0f172a] dark:text-[#f8fafc] font-mono focus:outline-none"
              />
            </div>
            <button
              type="submit"
              className="px-3 py-1.5 bg-white hover:bg-slate-50 dark:bg-[#0f172a] dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] text-[#0284c7] dark:text-[#38bdf8] rounded text-xs font-semibold cursor-pointer shrink-0"
            >
              Go
            </button>
          </form>
        </div>

        {/* Explorer Body: Left Sidebar + Right Files List */}
        <div className="flex-1 flex overflow-hidden">
          {/* Left Sidebar: Quick Access & Drives */}
          <div className="w-56 bg-[#f1f5f9] dark:bg-[#0f172a] border-r border-[#cbd5e1] dark:border-[#334155] flex flex-col p-3 space-y-4 shrink-0 overflow-y-auto">
            {/* Quick Access */}
            <div className="space-y-1">
              <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 font-mono px-2 py-1">
                Quick Access
              </div>
              <div className="space-y-0.5">
                {quickAccess.map((item) => {
                  let Icon = Folder;
                  if (item.name === 'Desktop') Icon = Monitor;
                  else if (item.name === 'Downloads') Icon = Download;
                  else if (item.name === 'Documents') Icon = FileText;
                  else if (item.name === 'User Profile') Icon = Home;
                  else if (item.name.includes('Cases')) Icon = HardDrive;

                  const isActive = currentPath.toLowerCase() === item.path.toLowerCase();

                  return (
                    <button
                      key={item.name}
                      type="button"
                      onClick={() => loadDirectory(item.path)}
                      className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded text-xs text-left transition-colors cursor-pointer ${
                        isActive
                          ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0284c7] dark:text-[#38bdf8] font-semibold border border-[#0284c7] dark:border-[#38bdf8]'
                          : 'text-[#0f172a] dark:text-slate-300 hover:bg-white dark:hover:bg-[#1e293b]'
                      }`}
                    >
                      <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-[#0284c7] dark:text-[#38bdf8]' : 'text-slate-400'}`} />
                      <span className="truncate">{item.name}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Logical Drives */}
            <div className="space-y-1">
              <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 font-mono px-2 py-1">
                Drives & Storage
              </div>
              <div className="space-y-0.5">
                {drives.map((d) => {
                  const isActive = currentPath.toLowerCase() === d.path.toLowerCase();
                  return (
                    <button
                      key={d.name}
                      type="button"
                      onClick={() => loadDirectory(d.path)}
                      className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded text-xs text-left transition-colors cursor-pointer ${
                        isActive
                          ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0284c7] dark:text-[#38bdf8] font-semibold border border-[#0284c7] dark:border-[#38bdf8]'
                          : 'text-[#0f172a] dark:text-slate-300 hover:bg-white dark:hover:bg-[#1e293b]'
                      }`}
                    >
                      <HardDrive className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-[#0284c7] dark:text-[#38bdf8]' : 'text-slate-400'}`} />
                      <span className="font-mono font-medium">{d.name}</span>
                      <span className="text-[10px] text-slate-400 ml-auto font-sans">Drive</span>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Right Main List Pane */}
          <div className="flex-1 flex flex-col overflow-hidden bg-white dark:bg-[#1e293b]">
            {/* Filter / Search Bar */}
            <div className="p-2 border-b border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] flex items-center justify-between gap-3 shrink-0">
              <div className="relative flex-1 max-w-xs">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Filter current view..."
                  className="w-full bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded pl-8 pr-3 py-1 text-xs text-[#0f172a] dark:text-[#f8fafc] placeholder-slate-400 focus:outline-none focus:border-[#0284c7]"
                />
                {searchTerm && (
                  <button
                    type="button"
                    onClick={() => setSearchTerm('')}
                    className="absolute right-2 top-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              {mode === 'file' && (
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => setShowImagesOnly(true)}
                    className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                      showImagesOnly
                        ? 'bg-[#0284c7] text-white border border-[#0369a1]'
                        : 'bg-white dark:bg-[#0f172a] text-slate-700 dark:text-slate-300 border border-[#cbd5e1] dark:border-[#334155]'
                    }`}
                  >
                    Images & Archives
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowImagesOnly(false)}
                    className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                      !showImagesOnly
                        ? 'bg-[#0284c7] text-white border border-[#0369a1]'
                        : 'bg-white dark:bg-[#0f172a] text-slate-700 dark:text-slate-300 border border-[#cbd5e1] dark:border-[#334155]'
                    }`}
                  >
                    All Files
                  </button>
                </div>
              )}
            </div>

            {/* Error Banner */}
            {error && (
              <div className="m-3 p-2.5 rounded badge-status-error text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-[#991b1b] shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* File & Folder Table */}
            <div className="flex-1 overflow-y-auto">
              {isLoading ? (
                <div className="h-full flex flex-col items-center justify-center text-slate-500 gap-2">
                  <Loader2 className="w-6 h-6 animate-spin text-[#0284c7]" />
                  <span className="text-xs font-mono">Reading files...</span>
                </div>
              ) : filteredEntries.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-slate-500 p-8 text-center">
                  <FolderOpen className="w-8 h-8 text-slate-400 mb-2" />
                  <div className="text-xs font-medium text-slate-600 dark:text-slate-300">No matching files or folders found</div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    {mode === 'file' && showImagesOnly
                      ? 'No disk images (.E01, .VHDX, .VMDK, .RAW, .ISO) in this folder. Toggle "All Files" above if needed.'
                      : 'This directory appears to be empty.'}
                  </div>
                </div>
              ) : (
                <table className="w-full text-left text-xs border-collapse">
                  <thead className="bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] text-[11px] text-slate-600 dark:text-slate-400 sticky top-0 z-10 font-mono">
                    <tr>
                      <th className="py-2 px-3 font-semibold">Name</th>
                      <th className="py-2 px-3 font-semibold w-28">Type</th>
                      <th className="py-2 px-3 font-semibold w-24 text-right">Size</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#e2e8f0] dark:divide-[#334155] font-sans">
                    {filteredEntries.map((entry) => {
                      const isSelected = selectedItemPath === entry.path;
                      const isImageFile = entry.is_image;

                      let Icon = File;
                      let iconColor = 'text-slate-400';

                      if (entry.is_drive) {
                        Icon = HardDrive;
                        iconColor = 'text-[#0284c7] dark:text-[#38bdf8]';
                      } else if (entry.is_dir) {
                        Icon = Folder;
                        iconColor = 'text-slate-500';
                      } else if (isImageFile) {
                        Icon = Disc;
                        iconColor = 'text-[#0284c7] dark:text-[#38bdf8]';
                      } else if (entry.is_archive) {
                        Icon = FileArchive;
                        iconColor = 'text-slate-500';
                      }

                      return (
                        <tr
                          key={entry.path}
                          onClick={() => handleItemClick(entry)}
                          onDoubleClick={() => handleItemDoubleClick(entry)}
                          className={`cursor-pointer transition-colors group ${
                            isSelected
                              ? 'bg-[#bae6fd] dark:bg-[#0c4a6e] text-[#0f172a] dark:text-[#f8fafc]'
                              : 'hover:bg-slate-50 dark:hover:bg-[#334155]'
                          }`}
                        >
                          <td className="py-2 px-3 flex items-center gap-2.5 min-w-0">
                            <Icon className={`w-4 h-4 shrink-0 ${iconColor}`} />
                            <span className="truncate font-medium">{entry.name}</span>
                            {isImageFile && (
                              <span className="ml-1.5 px-1.5 py-0.2 rounded bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] text-[10px] font-mono text-[#0284c7] dark:text-[#38bdf8] font-bold shrink-0">
                                IMAGE
                              </span>
                            )}
                          </td>
                          <td className="py-2 px-3 text-slate-500 dark:text-slate-400 text-[11px] truncate font-mono">
                            {entry.is_drive
                              ? 'Logical Drive'
                              : entry.is_dir
                              ? 'File Folder'
                              : entry.extension?.toUpperCase() || 'File'}
                          </td>
                          <td className="py-2 px-3 text-right text-slate-500 dark:text-slate-400 text-[11px] font-mono">
                            {entry.formatted_size || (entry.is_dir ? '—' : '')}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="h-14 bg-[#f1f5f9] dark:bg-[#0f172a] border-t border-[#cbd5e1] dark:border-[#334155] px-4 flex items-center justify-between shrink-0">
          <div className="flex-1 min-w-0 mr-4">
            <div className="text-[10px] uppercase font-mono text-slate-500 dark:text-slate-400">Selected Path</div>
            <div className="text-xs text-[#0284c7] dark:text-[#38bdf8] font-mono truncate font-semibold">
              {selectedItemPath || (mode === 'folder' && currentPath ? currentPath : 'No selection')}
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {mode === 'folder' && currentPath && (
              <button
                type="button"
                onClick={() => {
                  setSelectedItemPath(currentPath);
                  onSelect(currentPath);
                  onClose();
                }}
                className="px-3 py-1.5 bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] text-slate-700 dark:text-slate-300 rounded text-xs font-semibold cursor-pointer transition-colors"
                title="Select current directory"
              >
                Select Current Folder
              </button>
            )}

            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] text-slate-700 dark:text-slate-300 rounded text-xs font-semibold cursor-pointer transition-colors"
            >
              Cancel
            </button>

            <button
              type="button"
              onClick={handleConfirm}
              disabled={!selectedItemPath && !(mode === 'folder' && currentPath)}
              className="flex items-center gap-1.5 px-4 py-1.5 bg-[#0284c7] hover:bg-[#0369a1] disabled:opacity-40 text-white rounded text-xs font-bold cursor-pointer transition-all border border-[#0369a1] shadow-2xs"
            >
              <Check className="w-3.5 h-3.5" />
              <span>Confirm Selection</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
