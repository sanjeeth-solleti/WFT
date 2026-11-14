import React, { useState, useEffect, useMemo } from 'react';
import {
  Search,
  Check,
  X,
  Filter,
  RotateCcw,
  Loader2
} from 'lucide-react';
import { apiClient, DistinctValueItem } from '../api/client';

interface ColumnFilterPopoverProps {
  caseId: string;
  tableName: string;
  columnName: string;
  currentFilterValues: unknown[] | undefined;
  onApplyFilter: (columnName: string, selectedValues: unknown[]) => void;
  onClearFilter: (columnName: string) => void;
  onClose: () => void;
  position?: { top: number; left: number };
}

export const ColumnFilterPopover: React.FC<ColumnFilterPopoverProps> = ({
  caseId,
  tableName,
  columnName,
  currentFilterValues,
  onApplyFilter,
  onClearFilter,
  onClose,
  position,
}) => {
  const [items, setItems] = useState<DistinctValueItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedSet, setSelectedSet] = useState<Set<string>>(() => {
    if (currentFilterValues && currentFilterValues.length > 0) {
      return new Set(currentFilterValues.map((v) => String(v ?? '')));
    }
    return new Set();
  });
  const [isInitialSelectionAll, setIsInitialSelectionAll] = useState<boolean>(
    !currentFilterValues || currentFilterValues.length === 0
  );

  // Fetch distinct values on mount
  useEffect(() => {
    let isMounted = true;
    setIsLoading(true);
    setError(null);

    apiClient
      .getDistinctColumnValues(caseId, tableName, columnName)
      .then((data) => {
        if (!isMounted) return;
        setItems(data);
        if (isInitialSelectionAll) {
          setSelectedSet(new Set(data.map((item) => String(item.value ?? ''))));
        }
      })
      .catch((err) => {
        if (!isMounted) return;
        setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (isMounted) setIsLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [caseId, tableName, columnName, isInitialSelectionAll]);

  const filteredItems = useMemo(() => {
    if (!searchQuery.trim()) return items;
    const q = searchQuery.toLowerCase();
    return items.filter((item) =>
      String(item.value ?? '').toLowerCase().includes(q)
    );
  }, [items, searchQuery]);

  const areAllFilteredSelected = useMemo(() => {
    if (filteredItems.length === 0) return false;
    return filteredItems.every((item) => selectedSet.has(String(item.value ?? '')));
  }, [filteredItems, selectedSet]);

  const toggleSelectAll = () => {
    setSelectedSet((prev) => {
      const next = new Set(prev);
      if (areAllFilteredSelected) {
        filteredItems.forEach((item) => next.delete(String(item.value ?? '')));
      } else {
        filteredItems.forEach((item) => next.add(String(item.value ?? '')));
      }
      return next;
    });
  };

  const toggleItem = (val: unknown) => {
    const key = String(val ?? '');
    setSelectedSet((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  const handleApply = () => {
    if (items.length > 0 && selectedSet.size === items.length) {
      onClearFilter(columnName);
    } else {
      const selectedValues = Array.from(selectedSet);
      onApplyFilter(columnName, selectedValues);
    }
    onClose();
  };

  const handleClear = () => {
    onClearFilter(columnName);
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-xs p-4 select-none"
      onClick={onClose}
    >
      <div
        className="w-80 max-w-full bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] rounded shadow-2xl overflow-hidden flex flex-col font-sans text-xs text-[#0f172a] dark:text-[#f8fafc] animate-in fade-in zoom-in-95 duration-150"
        style={
          position
            ? {
                position: 'absolute',
                top: Math.min(position.top, window.innerHeight - 380),
                left: Math.min(position.left, window.innerWidth - 340),
                margin: 0,
              }
            : undefined
        }
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-3.5 py-2.5 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between">
          <div className="flex items-center gap-2 min-w-0">
            <Filter className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8] shrink-0" />
            <span className="font-bold truncate text-[#0f172a] dark:text-[#f8fafc] uppercase tracking-wide text-xs">
              Filter: {columnName}
            </span>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-slate-200 dark:hover:bg-[#334155] text-slate-500 hover:text-[#0f172a] dark:hover:text-white transition-colors cursor-pointer"
            title="Close"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Quick Search */}
        <div className="p-2.5 border-b border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b]">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2 text-slate-400 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search distinct values..."
              autoFocus
              className="w-full bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] focus:border-[#0284c7] rounded pl-8 pr-7 py-1 text-xs text-[#0f172a] dark:text-[#f8fafc] placeholder-slate-400 focus:outline-none font-sans"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>

        {/* Select All Checkbox */}
        <div className="px-3 py-2 border-b border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] flex items-center justify-between">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={areAllFilteredSelected}
              onChange={toggleSelectAll}
              className="w-3.5 h-3.5 rounded border-[#cbd5e1] text-[#0284c7] focus:ring-0 cursor-pointer"
            />
            <span className="font-semibold text-[11.5px] text-[#0f172a] dark:text-[#f8fafc]">
              (Select All)
            </span>
          </label>
          <span className="text-[10.5px] font-mono text-slate-500 dark:text-slate-400">
            {selectedSet.size} of {items.length} selected
          </span>
        </div>

        {/* Distinct Values Scrollable List */}
        <div className="max-h-56 min-h-36 overflow-y-auto p-1.5 space-y-0.5 bg-white dark:bg-[#1e293b] divide-y divide-[#e2e8f0] dark:divide-[#334155]">
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-8 text-slate-400 gap-2">
              <Loader2 className="w-5 h-5 animate-spin text-[#0284c7] dark:text-[#38bdf8]" />
              <span className="text-[11px] font-mono">Fetching distinct values...</span>
            </div>
          ) : error ? (
            <div className="p-4 text-center text-[#991b1b] dark:text-red-400 text-xs">
              Failed to load distinct values: {error}
            </div>
          ) : filteredItems.length === 0 ? (
            <div className="p-4 text-center text-slate-400 italic text-xs">
              No matching values found.
            </div>
          ) : (
            filteredItems.map((item, idx) => {
              const valStr = String(item.value ?? '');
              const displayVal = valStr.trim() === '' ? '(empty)' : valStr;
              const isChecked = selectedSet.has(valStr);

              return (
                <label
                  key={`${valStr}-${idx}`}
                  className={`flex items-center justify-between px-2.5 py-1.5 rounded cursor-pointer transition-colors hover:bg-slate-100 dark:hover:bg-[#334155] ${
                    isChecked ? 'bg-[#bae6fd]/40 dark:bg-[#0c4a6e]/40' : ''
                  }`}
                >
                  <div className="flex items-center gap-2 min-w-0 pr-2">
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => toggleItem(item.value)}
                      className="w-3.5 h-3.5 rounded border-[#cbd5e1] text-[#0284c7] focus:ring-0 cursor-pointer shrink-0"
                    />
                    <span
                      className={`truncate font-mono text-[11.5px] ${
                        valStr === ''
                          ? 'text-slate-400 italic'
                          : isChecked
                          ? 'text-[#0284c7] dark:text-[#38bdf8] font-bold'
                          : 'text-[#0f172a] dark:text-[#f8fafc]'
                      }`}
                      title={valStr}
                    >
                      {displayVal}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-[#0f172a] text-slate-600 dark:text-slate-400 border border-[#cbd5e1] dark:border-[#334155] shrink-0">
                    {item.count.toLocaleString()}
                  </span>
                </label>
              );
            })
          )}
        </div>

        {/* Popover Footer: Apply & Clear Buttons */}
        <div className="p-2.5 bg-[#f1f5f9] dark:bg-[#0f172a] border-t border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between gap-2">
          <button
            onClick={handleClear}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] text-slate-700 dark:text-slate-300 border border-[#cbd5e1] dark:border-[#334155] font-semibold text-xs transition-colors cursor-pointer"
          >
            <RotateCcw className="w-3 h-3 text-slate-500" />
            <span>Clear</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-3 py-1.5 rounded hover:bg-slate-200 dark:hover:bg-[#334155] text-slate-600 dark:text-slate-300 font-medium text-xs transition-colors cursor-pointer"
            >
              Cancel
            </button>
            <button
              onClick={handleApply}
              disabled={isLoading}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded bg-[#0284c7] hover:bg-[#0369a1] text-white font-semibold text-xs border border-[#0369a1] shadow-2xs transition-colors disabled:opacity-50 cursor-pointer"
            >
              <Check className="w-3.5 h-3.5" />
              <span>Apply</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
