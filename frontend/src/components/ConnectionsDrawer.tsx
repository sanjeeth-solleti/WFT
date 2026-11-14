import React, { useEffect, useRef, useState, useMemo } from 'react';
import cytoscape, { Core } from 'cytoscape';
import {
  Network,
  X,
  Maximize2,
  Search,
  RefreshCw,
  Layers,
} from 'lucide-react';
import {
  apiClient,
  ConnectionsResponse,
} from '../api/client';

interface ConnectionsDrawerProps {
  caseId: string;
  activeEntity: string;
  onSelectEntity: (entityValue: string) => void;
  onClose?: () => void;
  isFullScreen?: boolean;
  width?: number;
}

export const ConnectionsDrawer: React.FC<ConnectionsDrawerProps> = ({
  caseId,
  activeEntity,
  onSelectEntity,
  onClose,
  isFullScreen = false,
  width,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  const [data, setData] = useState<ConnectionsResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchInput, setSearchInput] = useState('');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [layoutName, setLayoutName] = useState<'concentric' | 'cose' | 'circle' | 'breadthfirst'>('concentric');

  // Fetch connections data
  useEffect(() => {
    if (!caseId) return;

    let isMounted = true;
    setIsLoading(true);
    setError(null);

    apiClient
      .getEntityConnections(caseId, activeEntity || undefined)
      .then((res) => {
        if (isMounted) {
          setData(res);
          setSelectedNodeId(null);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setError(err instanceof Error ? err.message : String(err));
          setData(null);
        }
      })
      .finally(() => {
        if (isMounted) setIsLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [caseId, activeEntity]);

  // Initialize & render Cytoscape
  useEffect(() => {
    if (!containerRef.current || !data) return;

    if (cyRef.current) {
      cyRef.current.destroy();
      cyRef.current = null;
    }

    const elements = [
      ...data.nodes.map((n) => ({
        group: 'nodes' as const,
        data: n.data,
      })),
      ...data.edges.map((e) => ({
        group: 'edges' as const,
        data: e.data,
      })),
    ];

    if (elements.length === 0) return;

    try {
      const cy = cytoscape({
        container: containerRef.current,
        elements,
        boxSelectionEnabled: false,
        autounselectify: false,
        style: [
          // Primary Center Entity Node
          {
            selector: 'node[type = "PRIMARY_ENTITY"]',
            style: {
              'background-color': '#0284c7', // WFT Blue
              'border-color': '#0369a1',
              'border-width': 2,
              label: 'data(label)',
              color: '#0f172a',
              'font-size': '11px',
              'font-family': 'monospace',
              'text-valign': 'center',
              'text-halign': 'center',
              'text-outline-color': '#ffffff',
              'text-outline-width': 2,
              width: 48,
              height: 48,
            },
          },
          // Artifact Nodes (Category radiating)
          {
            selector: 'node[type = "ARTIFACT_NODE"]',
            style: {
              'background-color': '#475569',
              'border-color': '#334155',
              'border-width': 1.5,
              label: 'data(label)',
              color: '#334155',
              'font-size': '10px',
              'font-family': 'monospace',
              'text-valign': 'bottom',
              'text-margin-y': 4,
              'text-outline-color': '#ffffff',
              'text-outline-width': 1.5,
              width: 30,
              height: 30,
            },
          },
          // Edges
          {
            selector: 'edge',
            style: {
              width: 1.5,
              'line-color': '#94a3b8',
              'curve-style': 'bezier',
              'target-arrow-shape': 'triangle',
              'target-arrow-color': '#64748b',
              'arrow-scale': 0.8,
              label: 'data(label)',
              'font-size': '8.5px',
              'font-family': 'monospace',
              color: '#475569',
              'text-outline-color': '#ffffff',
              'text-outline-width': 1,
            },
          },
          // Selected Node
          {
            selector: 'node:selected',
            style: {
              'border-color': '#0284c7',
              'border-width': 3,
            },
          },
        ] as any,
        layout: {
          name: layoutName,
          padding: 30,
          animate: true,
          animationDuration: 400,
        },
      });

      cy.on('tap', 'node', (evt) => {
        const node = evt.target;
        setSelectedNodeId(node.id());
        const nodeData = node.data();
        if (nodeData.type === 'PRIMARY_ENTITY' && nodeData.label !== activeEntity) {
          onSelectEntity(nodeData.label);
        }
      });

      cyRef.current = cy;
      cy.fit();
    } catch (err) {
      console.error('Cytoscape rendering failed:', err);
    }

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [data, layoutName, activeEntity, onSelectEntity]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchInput.trim()) {
      onSelectEntity(searchInput.trim());
      setSearchInput('');
    }
  };

  const handleFit = () => {
    if (cyRef.current) {
      cyRef.current.fit();
    }
  };

  const displayedOccurrences = useMemo(() => {
    if (!data?.occurrences) return [];
    if (!selectedNodeId || !selectedNodeId.startsWith('artifact_')) {
      return data.occurrences;
    }
    const clickedLabel = cyRef.current?.getElementById(selectedNodeId)?.data('label');
    if (!clickedLabel) return data.occurrences;
    return data.occurrences.filter((o) => o.artifact_name === clickedLabel);
  }, [data?.occurrences, selectedNodeId]);

  if (!caseId) {
    return (
      <aside
        className={`bg-white dark:bg-[#1e293b] border-l border-[#cbd5e1] dark:border-[#334155] flex flex-col items-center justify-center h-full select-none shadow-xl p-6 text-slate-500 gap-3 ${
          isFullScreen ? 'w-full' : 'w-96 shrink-0'
        }`}
      >
        <Network className="w-10 h-10 text-slate-400 mb-1" />
        <span className="font-bold text-[#0f172a] dark:text-[#f8fafc] text-sm">No Active Case</span>
        <span className="text-xs text-slate-500 text-center">
          Open or process a case to visualize entity connections.
        </span>
      </aside>
    );
  }

  return (
    <aside
      style={{ width: isFullScreen ? undefined : width ? `${width}px` : undefined }}
      className={`bg-white dark:bg-[#1e293b] border-l border-[#cbd5e1] dark:border-[#334155] flex flex-col h-full select-none shadow-xl ${
        isFullScreen ? 'w-full' : width ? 'shrink-0' : 'w-96 shrink-0'
      }`}
    >
      {/* Drawer Header */}
      <div className="h-12 px-3 bg-[#f1f5f9] dark:bg-[#0f172a] border-b border-[#cbd5e1] dark:border-[#334155] flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2 overflow-hidden">
          <div className="p-1.5 rounded bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] text-[#0284c7] dark:text-[#38bdf8]">
            <Network className="w-4 h-4" />
          </div>
          <div className="flex flex-col overflow-hidden">
            <span className="font-bold text-xs text-[#0f172a] dark:text-[#f8fafc] flex items-center gap-1.5 truncate">
              WFT Connections
            </span>
            <span className="text-[10px] font-mono text-[#0284c7] dark:text-[#38bdf8] truncate font-semibold">
              {activeEntity ? activeEntity : 'Cross-Artifact Hub Overview'}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={handleFit}
            className="p-1 rounded bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] border border-[#cbd5e1] dark:border-[#334155] text-slate-700 dark:text-slate-300 text-xs cursor-pointer"
            title="Reset Graph Zoom / Fit"
          >
            <Maximize2 className="w-3.5 h-3.5" />
          </button>

          {onClose && !isFullScreen && (
            <button
              onClick={onClose}
              className="p-1 rounded hover:bg-slate-200 dark:hover:bg-[#334155] text-slate-500 hover:text-[#0f172a] dark:hover:text-white cursor-pointer"
              title="Close Drawer"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Entity Search & Layout Controls */}
      <div className="p-2 border-b border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] flex items-center gap-2">
        <form onSubmit={handleSearchSubmit} className="relative flex-1">
          <Search className="w-3 h-3 absolute left-2 top-2 text-slate-400" />
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search entity (EXE, IP, Hash)..."
            className="w-full bg-[#f8fafc] dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] rounded pl-7 pr-2 py-1 text-xs text-[#0f172a] dark:text-[#f8fafc] placeholder-slate-400 font-mono focus:outline-none focus:border-[#0284c7]"
          />
        </form>

        <select
          value={layoutName}
          onChange={(e) => setLayoutName(e.target.value as any)}
          className="bg-white dark:bg-[#0f172a] border border-[#cbd5e1] dark:border-[#334155] text-[#0f172a] dark:text-[#f8fafc] rounded px-2 py-1 text-xs font-mono focus:outline-none cursor-pointer"
          title="Graph Layout Algorithm"
        >
          <option value="concentric">Concentric</option>
          <option value="cose">Force Cose</option>
          <option value="circle">Circle</option>
          <option value="breadthfirst">Hierarchical</option>
        </select>
      </div>

      {/* Top 50 Quick Selection Carousel (when in overview mode) */}
      {!activeEntity && data?.top_entities && data.top_entities.length > 0 && (
        <div className="p-2 border-b border-[#cbd5e1] dark:border-[#334155] bg-[#f8fafc] dark:bg-[#0f172a]">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 block mb-1">
            Top Connected Forensic Hubs:
          </span>
          <div className="flex flex-wrap gap-1 max-h-20 overflow-y-auto">
            {data.top_entities.slice(0, 15).map((te) => (
              <button
                key={te.entity_value}
                onClick={() => onSelectEntity(te.entity_value)}
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-white hover:bg-slate-50 dark:bg-[#1e293b] dark:hover:bg-[#334155] text-[#0f172a] dark:text-[#f8fafc] border border-[#cbd5e1] dark:border-[#334155] flex items-center gap-1 transition-colors cursor-pointer shadow-2xs"
              >
                <span>{te.entity_value}</span>
                <span className="text-[#0284c7] dark:text-[#38bdf8] font-bold">({te.artifact_count})</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Main Cytoscape Graph Canvas Area */}
      <div className={`relative bg-slate-50 dark:bg-[#0f172a] flex-1 overflow-hidden ${isFullScreen ? 'min-h-[400px]' : 'min-h-[260px]'}`}>
        {isLoading && (
          <div className="absolute inset-0 bg-white/70 dark:bg-[#0f172a]/70 z-20 flex items-center justify-center">
            <RefreshCw className="w-5 h-5 text-[#0284c7] dark:text-[#38bdf8] animate-spin" />
          </div>
        )}

        {error ? (
          <div className="p-4 text-center text-[#991b1b] dark:text-red-400 text-xs font-mono">{error}</div>
        ) : !data || data.nodes.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 text-xs italic gap-1 p-4 text-center">
            <Network className="w-8 h-8 text-slate-400" />
            <span>No connections recorded for entity '{activeEntity}'.</span>
            <span className="text-[10px] text-slate-400">
              Run EZ tools and non-EZ parsers to index cross-artifact relationships.
            </span>
          </div>
        ) : (
          <div ref={containerRef} className="w-full h-full" />
        )}
      </div>

      {/* Linked Evidentiary Records Section (Occurrences) */}
      <div className={`border-t border-[#cbd5e1] dark:border-[#334155] bg-white dark:bg-[#1e293b] flex flex-col ${isFullScreen ? 'h-64' : 'h-52'}`}>
        <div className="px-3 py-1.5 border-b border-[#cbd5e1] dark:border-[#334155] bg-[#f1f5f9] dark:bg-[#0f172a] flex items-center justify-between text-xs">
          <div className="flex items-center gap-1.5 font-semibold text-[#0f172a] dark:text-[#f8fafc]">
            <Layers className="w-3.5 h-3.5 text-[#0284c7] dark:text-[#38bdf8]" />
            <span>Correlated Occurrences ({displayedOccurrences.length})</span>
          </div>
          {selectedNodeId && (
            <button
              onClick={() => setSelectedNodeId(null)}
              className="text-[10px] text-[#0284c7] dark:text-[#38bdf8] hover:underline font-mono cursor-pointer font-semibold"
            >
              Reset filter
            </button>
          )}
        </div>

        <div className="flex-1 overflow-y-auto p-2 space-y-1 text-xs font-mono select-text bg-[#f8fafc] dark:bg-[#0f172a]">
          {displayedOccurrences.length === 0 ? (
            <div className="text-slate-500 text-center py-4 italic text-[11px]">
              No individual occurrences matched.
            </div>
          ) : (
            displayedOccurrences.map((occ) => (
              <div
                key={occ.connection_id}
                className="p-2 rounded bg-white dark:bg-[#1e293b] border border-[#cbd5e1] dark:border-[#334155] hover:border-slate-400 flex flex-col gap-0.5 shadow-2xs"
              >
                <div className="flex items-center justify-between text-[10px]">
                  <span className="font-semibold text-[#0284c7] dark:text-[#38bdf8]">{occ.artifact_name}</span>
                  <span className="text-slate-500">
                    {occ.timestamp_utc ? occ.timestamp_utc.replace('T', ' ').slice(0, 19) : 'No Timestamp'}
                  </span>
                </div>
                <div className="text-[#0f172a] dark:text-[#f8fafc] text-[11px] truncate">
                  {occ.context_label || occ.entity_value}
                </div>
                <div className="text-[9px] text-slate-500 flex items-center gap-2">
                  <span>Table: {occ.source_table}</span>
                  <span>Row: #{occ.source_row_id}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </aside>
  );
};
