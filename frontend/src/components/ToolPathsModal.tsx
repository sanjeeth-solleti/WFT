import React, { useState, useEffect } from 'react';
import {
  X,
  Settings,
  FolderOpen,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Save,
  Wrench,
  ChevronDown,
  ChevronRight,
  Terminal,
  Cpu,
  Layers,
} from 'lucide-react';
import { apiClient, ToolPathsMap, ToolPathInfo } from '../api/client';
import { FileBrowserModal } from './FileBrowserModal';

interface ToolPathsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onPathsUpdated?: () => void;
}

export const ToolPathsModal: React.FC<ToolPathsModalProps> = ({
  isOpen,
  onClose,
  onPathsUpdated,
}) => {
  const [tools, setTools] = useState<ToolPathsMap | null>(null);
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [savedEnvPath, setSavedEnvPath] = useState<string | null>(null);
  const [fileBrowserOpen, setFileBrowserOpen] = useState(false);
  const [fileBrowserMode, setFileBrowserMode] = useState<'file' | 'folder'>('folder');
  const [activeBrowseKey, setActiveBrowseKey] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Auto-Installer states
  const [isRunningAutoSetup, setIsRunningAutoSetup] = useState(false);
  const [autoSetupOutput, setAutoSetupOutput] = useState<{
    status: string;
    message: string;
    stdout?: string;
  } | null>(null);

  // Expandable section for individual EZ tools
  const [isEzOverridesExpanded, setIsEzOverridesExpanded] = useState(false);

  const fetchPaths = async (scan: boolean = false) => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const data = await apiClient.getToolPaths(scan);
      // Filter out internal non-tool entries (YARA rules, Cases storage)
      const filteredTools: ToolPathsMap = {};
      const initialForm: Record<string, string> = {};

      Object.entries(data).forEach(([key, info]) => {
        if (
          key === 'rules' ||
          key === 'cases' ||
          key === 'yara_x' ||
          key === 'cases_dir' ||
          key.includes('RULES_DIR') ||
          key.includes('CASES_DIR')
        ) {
          return;
        }
        filteredTools[key] = info;
        initialForm[key] = info.configured_path || info.path || info.resolved_path || '';
      });

      setTools(filteredTools);
      setFormData(initialForm);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load external tool paths');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchPaths();
      setSaveSuccess(false);
      setSavedEnvPath(null);
      setAutoSetupOutput(null);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleInputChange = (key: string, value: string) => {
    setFormData((prev) => ({ ...prev, [key]: value }));
    setSaveSuccess(false);
  };

  const handleBrowse = (key: string, isExecutable: boolean) => {
    setActiveBrowseKey(key);
    setFileBrowserMode(isExecutable ? 'file' : 'folder');
    setFileBrowserOpen(true);
  };

  const handleInAppSelect = (chosenPath: string) => {
    if (activeBrowseKey) {
      handleInputChange(activeBrowseKey, chosenPath);
    }
  };

  const handleSave = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setIsSaving(true);
    setErrorMsg(null);
    try {
      // Exclude forbidden internal directories
      const cleanData: Record<string, string> = {};
      Object.entries(formData).forEach(([k, v]) => {
        if (
          k !== 'rules' &&
          k !== 'cases' &&
          k !== 'yara_x' &&
          k !== 'cases_dir' &&
          !k.includes('RULES_DIR') &&
          !k.includes('CASES_DIR')
        ) {
          cleanData[k] = v;
        }
      });

      const res = await apiClient.saveToolPaths(cleanData);
      setTools(res.tools);
      setSavedEnvPath(res.env_file_path || '.env');
      setSaveSuccess(true);
      if (onPathsUpdated) onPathsUpdated();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to persist tool paths');
    } finally {
      setIsSaving(false);
    }
  };

  const handleRunAutoSetup = async () => {
    setIsRunningAutoSetup(true);
    setErrorMsg(null);
    setAutoSetupOutput(null);
    setSaveSuccess(false);

    try {
      const res = await apiClient.runAutoSetupTools();
      setAutoSetupOutput({
        status: res.status,
        message: res.message || 'WFT Toolchain Setup completed.',
        stdout: res.stdout,
      });

      if (res.tools) {
        setTools(res.tools);
        const updatedForm: Record<string, string> = { ...formData };
        Object.entries(res.tools).forEach(([k, info]) => {
          const p = info.configured_path || info.path || info.resolved_path || '';
          if (p) updatedForm[k] = p;
        });
        setFormData(updatedForm);
      } else {
        await fetchPaths();
      }

      if (onPathsUpdated) onPathsUpdated();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to execute WFT tool setup');
    } finally {
      setIsRunningAutoSetup(false);
    }
  };

  // Main 4 forensic engines (Strictly excluding YARA & Cases Folder)
  const mainToolKeys = ['ez_tools', 'regripper', 'hindsight', 'stinger'];

  // Individual EZ binaries
  const individualEzKeys = tools
    ? Object.keys(tools).filter(
        (k) =>
          (tools[k].category === 'individual_ez' || (k.startsWith('ez_') && k !== 'ez_tools')) &&
          k !== 'rules' &&
          k !== 'cases'
      )
    : [];

  const foundIndividualCount = individualEzKeys.filter(
    (k) => tools?.[k]?.status === 'FOUND'
  ).length;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 select-none">
      <div className="bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded-lg shadow-2xl w-full max-w-3xl flex flex-col max-h-[92vh] overflow-hidden font-sans">
        {/* Header */}
        <div className="px-5 py-3.5 bg-[#f8fafc] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded bg-blue-100 dark:bg-blue-950/60 text-[#0284c7] dark:text-[#38bdf8] border border-blue-200 dark:border-blue-800">
              <Settings className="w-4 h-4" />
            </div>
            <div>
              <h2 className="font-bold text-sm text-[#0f172a] dark:text-[#f8fafc]">
                External Tool Paths & Environment Manager
              </h2>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Configure master directories & individual 3-tier executable overrides in <span className="font-mono font-semibold">.env</span>
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSave} className="flex-1 overflow-y-auto p-5 space-y-4">
          {/* Quick Action: Auto-Setup Banner */}
          <div className="p-3.5 bg-gradient-to-r from-blue-50/70 to-indigo-50/50 dark:from-blue-950/30 dark:to-indigo-950/20 border border-blue-200/80 dark:border-blue-900/50 rounded-lg flex items-center justify-between gap-3 shadow-2xs">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-md bg-blue-600 text-white shrink-0 shadow-2xs">
                <Wrench className="w-4 h-4" />
              </div>
              <div>
                <h4 className="text-xs font-bold text-blue-950 dark:text-blue-200">
                  Automated Toolchain Discovery & Setup
                </h4>
                <p className="text-[11px] text-slate-600 dark:text-slate-400">
                  Scans system, downloads missing binaries to <span className="font-mono font-semibold">.\tools\</span>, and populates <span className="font-mono font-semibold">.env</span>.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={handleRunAutoSetup}
              disabled={isRunningAutoSetup || isLoading}
              className="px-3.5 py-1.5 rounded-md bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-semibold border border-[#0369a1] flex items-center gap-1.5 shadow-2xs cursor-pointer shrink-0 disabled:opacity-50 transition-colors"
            >
              {isRunningAutoSetup ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin text-white" />
                  <span>Installing...</span>
                </>
              ) : (
                <>
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Run WFT Auto-Installer (Setup-WFTTools.ps1)</span>
                </>
              )}
            </button>
          </div>

          {/* Auto-Setup Log Result */}
          {autoSetupOutput && (
            <div className="p-3 bg-slate-900 text-slate-200 rounded border border-slate-700 font-mono text-[11px] space-y-1.5 shadow-inner">
              <div className="flex items-center gap-2 text-emerald-400 font-bold">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{autoSetupOutput.message}</span>
              </div>
              {autoSetupOutput.stdout && (
                <pre className="max-h-24 overflow-y-auto text-[10px] text-slate-400 whitespace-pre-wrap leading-tight">
                  {autoSetupOutput.stdout}
                </pre>
              )}
            </div>
          )}

          {errorMsg && (
            <div className="p-3 bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 rounded flex items-center gap-2 text-xs text-rose-700 dark:text-rose-300">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {saveSuccess && (
            <div className="p-3 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-800 rounded-md flex flex-col gap-1.5 text-xs text-emerald-800 dark:text-emerald-200 shadow-2xs">
              <div className="flex items-center gap-2 font-bold text-emerald-700 dark:text-emerald-300">
                <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
                <span>Tool paths successfully saved and environment reloaded!</span>
              </div>
              <div className="flex items-center gap-2 text-[11px] font-mono bg-white/70 dark:bg-[#0f172a]/70 px-2.5 py-1.5 rounded border border-emerald-200 dark:border-emerald-800/60 select-all">
                <span className="text-slate-500 dark:text-slate-400 font-sans font-semibold">Persisted to:</span>
                <span className="font-bold text-emerald-900 dark:text-emerald-200">{savedEnvPath || '.env'}</span>
              </div>
            </div>
          )}

          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12 text-slate-400 gap-2">
              <RefreshCw className="w-6 h-6 animate-spin text-[#0284c7]" />
              <span className="text-xs font-mono">Scanning and inspecting tool paths...</span>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Main Tools Section */}
              <div className="space-y-3">
                <div className="flex items-center gap-2 text-xs font-bold text-slate-700 dark:text-slate-300">
                  <Cpu className="w-3.5 h-3.5 text-slate-500" />
                  <span>Primary Forensic Engines & Master Folders</span>
                </div>

                {mainToolKeys.map((key) => {
                  const info: ToolPathInfo | undefined = tools?.[key];
                  if (!info) return null;
                  const isFound = info.status === 'FOUND' || info.status === 'HEURISTICS READY';
                  const isExecutable = key === 'stinger' || key === 'hindsight' || key === 'regripper';

                  return (
                    <div
                      key={key}
                      className="p-3.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc]/50 dark:bg-[#0f172a]/40 space-y-2 hover:border-slate-400 dark:hover:border-slate-500 transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-xs text-[#0f172a] dark:text-[#f8fafc]">
                            {info.name}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${
                              info.status === 'FOUND'
                                ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800'
                                : info.status === 'HEURISTICS READY'
                                ? 'bg-blue-100 dark:bg-blue-950/60 text-blue-800 dark:text-blue-300 border-blue-300 dark:border-blue-800'
                                : 'bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-800'
                            }`}
                          >
                            {info.status}
                          </span>
                        </div>
                        <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                          {info.env_var || key}
                        </span>
                      </div>

                      <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-tight">
                        {info.description}
                      </p>

                      <div className="flex items-center gap-2">
                        <input
                          type="text"
                          value={formData[key] ?? ''}
                          onChange={(e) => handleInputChange(key, e.target.value)}
                          placeholder={info.resolved_path || info.configured_path || `Path to ${info.name}`}
                          className="flex-1 px-2.5 py-1.5 text-xs font-mono bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded focus:outline-none focus:border-[#0284c7] text-[#0f172a] dark:text-[#f8fafc]"
                        />
                        <button
                          type="button"
                          onClick={() => handleBrowse(key, isExecutable)}
                          className="px-2.5 py-1.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white hover:bg-slate-100 dark:bg-[#1e293b] dark:hover:bg-[#334155] text-xs font-semibold text-[#0f172a] dark:text-[#f8fafc] flex items-center gap-1.5 cursor-pointer shrink-0"
                          title={isExecutable ? 'Browse for executable...' : 'Browse for folder...'}
                        >
                          <FolderOpen className="w-3.5 h-3.5 text-slate-500" />
                          <span>Browse...</span>
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Expandable/Collapsible Section: Individual EZ Tool Overrides */}
              <div className="border border-[#cbd5e1] dark:border-[#334155] rounded-lg overflow-hidden bg-white dark:bg-[#1e293b]/60">
                <button
                  type="button"
                  onClick={() => setIsEzOverridesExpanded((prev) => !prev)}
                  className="w-full px-4 py-3 bg-[#f1f5f9] dark:bg-[#0f172a] hover:bg-[#e2e8f0] dark:hover:bg-[#1e293b] transition-colors flex items-center justify-between cursor-pointer text-left border-b border-transparent data-[expanded=true]:border-[#cbd5e1] dark:data-[expanded=true]:border-[#334155]"
                  data-expanded={isEzOverridesExpanded}
                >
                  <div className="flex items-center gap-2.5">
                    {isEzOverridesExpanded ? (
                      <ChevronDown className="w-4 h-4 text-slate-500" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-slate-500" />
                    )}
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-xs text-[#0f172a] dark:text-[#f8fafc]">
                          Individual EZ Tool Overrides (For Custom / Standalone Installs)
                        </span>
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold font-mono bg-blue-100 dark:bg-blue-950/80 text-blue-800 dark:text-blue-300 border border-blue-300 dark:border-blue-800">
                          {foundIndividualCount}/{individualEzKeys.length} FOUND
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                        Optionally specify standalone binary paths. 3-tier priority: individual .env override &gt; master directory search &gt; system PATH.
                      </p>
                    </div>
                  </div>
                  <div className="text-[11px] font-semibold text-slate-400">
                    {isEzOverridesExpanded ? 'Hide' : 'Expand'}
                  </div>
                </button>

                {isEzOverridesExpanded && (
                  <div className="p-4 space-y-3 bg-[#f8fafc]/30 dark:bg-[#0f172a]/20 max-h-[380px] overflow-y-auto">
                    {individualEzKeys.length === 0 ? (
                      <p className="text-xs text-slate-400 italic">No individual EZ tool definitions loaded.</p>
                    ) : (
                      individualEzKeys.map((k) => {
                        const item = tools?.[k];
                        if (!item) return null;
                        const isFound = item.status === 'FOUND';

                        return (
                          <div
                            key={k}
                            className="p-3 rounded border border-slate-200 dark:border-slate-700/80 bg-white dark:bg-[#1e293b] space-y-1.5 shadow-2xs"
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className="font-bold text-xs text-[#0f172a] dark:text-[#f8fafc]">
                                  {item.name}
                                </span>
                                <span
                                  className={`px-1.5 py-0.2 rounded text-[10px] font-bold font-mono border ${
                                    isFound
                                      ? 'bg-emerald-100 dark:bg-emerald-950/60 text-emerald-800 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800'
                                      : 'bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-800'
                                  }`}
                                >
                                  {item.status}
                                </span>
                              </div>
                              <span className="text-[10px] font-mono text-slate-400">
                                {item.env_var}
                              </span>
                            </div>

                            <p className="text-[10px] text-slate-500 dark:text-slate-400 leading-tight">
                              {item.description}
                            </p>

                            <div className="flex items-center gap-2 pt-0.5">
                              <input
                                type="text"
                                value={formData[k] ?? ''}
                                onChange={(e) => handleInputChange(k, e.target.value)}
                                placeholder={item.resolved_path || item.configured_path || `Path to ${item.binary || 'executable'}`}
                                className="flex-1 px-2 py-1 text-xs font-mono bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded focus:outline-none focus:border-[#0284c7] text-[#0f172a] dark:text-[#f8fafc]"
                              />
                              <button
                                type="button"
                                onClick={() => handleBrowse(k, true)}
                                className="px-2 py-1 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white hover:bg-slate-100 dark:bg-[#1e293b] dark:hover:bg-[#334155] text-xs font-semibold text-[#0f172a] dark:text-[#f8fafc] flex items-center gap-1 cursor-pointer shrink-0"
                                title="Browse for executable file..."
                              >
                                <FolderOpen className="w-3 h-3 text-slate-500" />
                                <span>Browse...</span>
                              </button>
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </form>

        {/* Footer */}
        <div className="px-5 py-3 bg-[#f8fafc] dark:bg-[#0f172a] border-t border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0">
          <button
            type="button"
            onClick={() => fetchPaths(true)}
            disabled={isLoading || isRunningAutoSetup}
            className="px-3 py-1.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white hover:bg-slate-100 dark:bg-[#1e293b] dark:hover:bg-[#334155] text-xs font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-[#0284c7]' : ''}`} />
            <span>Re-scan Tools</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-1.5 rounded border border-[#cbd5e1] dark:border-[#334155] bg-white hover:bg-slate-100 dark:bg-[#1e293b] dark:hover:bg-[#334155] text-xs font-semibold text-slate-700 dark:text-slate-300 cursor-pointer"
            >
              Close
            </button>
            <button
              type="button"
              onClick={() => handleSave()}
              disabled={isSaving || isRunningAutoSetup}
              className="px-4 py-1.5 rounded bg-[#0284c7] hover:bg-[#0369a1] text-white text-xs font-semibold border border-[#0369a1] flex items-center gap-1.5 shadow-xs cursor-pointer disabled:opacity-50"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{isSaving ? 'Saving...' : 'Save & Reload Environment'}</span>
            </button>
          </div>
        </div>
      </div>

      <FileBrowserModal
        isOpen={fileBrowserOpen}
        onClose={() => setFileBrowserOpen(false)}
        onSelect={handleInAppSelect}
        mode={fileBrowserMode}
        title={fileBrowserMode === 'file' ? 'Select Executable File' : 'Select Tool Directory'}
        initialPath={activeBrowseKey ? formData[activeBrowseKey] : undefined}
      />
    </div>
  );
};