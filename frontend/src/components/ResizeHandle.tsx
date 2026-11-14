import React, { useState, useEffect, useCallback, useRef } from 'react';

// ============================================================================
// Visual Resize Handle Component (Horizontal or Vertical Divider)
// ============================================================================
export interface ResizeHandleProps {
  orientation?: 'vertical' | 'horizontal'; // 'vertical' = divider between columns (col-resize), 'horizontal' = divider between rows (row-resize)
  onMouseDown: (e: React.MouseEvent) => void;
  onDoubleClick?: () => void;
  isDragging?: boolean;
  title?: string;
  className?: string;
}

export const ResizeHandle: React.FC<ResizeHandleProps> = ({
  orientation = 'vertical',
  onMouseDown,
  onDoubleClick,
  isDragging = false,
  title,
  className = '',
}) => {
  const isCol = orientation === 'vertical';

  return (
    <>
      <div
        onMouseDown={onMouseDown}
        onDoubleClick={onDoubleClick}
        className={`group relative flex items-center justify-center shrink-0 select-none z-20 transition-all ${
          isCol
            ? `w-1.5 hover:w-2 cursor-col-resize ${
                isDragging
                  ? 'w-2 bg-[#0284c7] dark:bg-[#38bdf8]'
                  : 'bg-[#cbd5e1] hover:bg-[#0284c7] dark:bg-[#334155] dark:hover:bg-[#38bdf8]'
              }`
            : `h-1.5 hover:h-2 cursor-row-resize ${
                isDragging
                  ? 'h-2 bg-[#0284c7] dark:bg-[#38bdf8]'
                  : 'bg-[#cbd5e1] hover:bg-[#0284c7] dark:bg-[#334155] dark:hover:bg-[#38bdf8]'
              }`
        } ${className}`}
        title={title || `Drag to resize pane (${onDoubleClick ? 'double-click to reset' : ''})`}
      >
        {/* Visual Grip Handle Indicator */}
        {isCol ? (
          <div
            className={`flex flex-col gap-0.5 items-center pointer-events-none transition-opacity ${
              isDragging ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'
            }`}
          >
            <div className="w-0.5 h-1 bg-white/90 rounded-full" />
            <div className="w-0.5 h-1 bg-white/90 rounded-full" />
            <div className="w-0.5 h-1 bg-white/90 rounded-full" />
          </div>
        ) : (
          <div
            className={`flex flex-row gap-0.5 items-center pointer-events-none transition-opacity ${
              isDragging ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'
            }`}
          >
            <div className="h-0.5 w-1 bg-white/90 rounded-full" />
            <div className="h-0.5 w-1 bg-white/90 rounded-full" />
            <div className="h-0.5 w-1 bg-white/90 rounded-full" />
          </div>
        )}
      </div>

      {/* Global transparent drag shield to prevent child elements (AG Grid, iframes, canvas) from capturing mouse events */}
      {isDragging && (
        <div
          className={`fixed inset-0 z-50 select-none pointer-events-auto ${
            isCol ? 'cursor-col-resize' : 'cursor-row-resize'
          }`}
          style={{ cursor: isCol ? 'col-resize' : 'row-resize' }}
        />
      )}
    </>
  );
};

// ============================================================================
// Custom Hook for Horizontal Resizing (Width in pixels for Left or Right Pane)
// ============================================================================
export interface UseResizableOptions {
  initialWidth: number;
  minWidth?: number;
  maxWidth?: number;
  storageKey?: string;
  direction?: 'left' | 'right'; // 'left' = pane on left of container, 'right' = pane on right of container
  containerRef: React.RefObject<HTMLElement | null>;
  otherWidth?: number; // width of opposite pane, to prevent squeezing center pane
  minCenterWidth?: number; // minimum pixels preserved for center pane (default 240)
}

export function useResizable({
  initialWidth,
  minWidth = 200,
  maxWidth = 750,
  storageKey,
  direction = 'left',
  containerRef,
  otherWidth = 0,
  minCenterWidth = 240,
}: UseResizableOptions) {
  const [width, setWidth] = useState<number>(() => {
    if (storageKey) {
      try {
        const stored = localStorage.getItem(storageKey);
        if (stored) {
          const val = Number(stored);
          if (!isNaN(val) && val >= minWidth && val <= maxWidth) {
            return val;
          }
        }
      } catch {
        // ignore
      }
    }
    return initialWidth;
  });

  const [isDragging, setIsDragging] = useState(false);

  // Keep a ref of latest params to avoid stale closures in window listeners
  const paramsRef = useRef({
    minWidth,
    maxWidth,
    direction,
    otherWidth,
    minCenterWidth,
    storageKey,
  });

  useEffect(() => {
    paramsRef.current = {
      minWidth,
      maxWidth,
      direction,
      otherWidth,
      minCenterWidth,
      storageKey,
    };
  }, [minWidth, maxWidth, direction, otherWidth, minCenterWidth, storageKey]);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const resetWidth = useCallback(() => {
    setWidth(initialWidth);
    if (storageKey) {
      try {
        localStorage.removeItem(storageKey);
      } catch {
        // ignore
      }
    }
  }, [initialWidth, storageKey]);

  useEffect(() => {
    if (!isDragging) return;

    const handleMouseMove = (e: MouseEvent) => {
      if (!containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const {
        minWidth: minW,
        maxWidth: maxW,
        direction: dir,
        otherWidth: otherW,
        minCenterWidth: minCenterW,
        storageKey: key,
      } = paramsRef.current;

      const maxAllowed = Math.max(
        minW,
        Math.min(maxW, rect.width - (otherW || 0) - minCenterW)
      );

      let calculatedWidth = initialWidth;
      if (dir === 'left') {
        calculatedWidth = Math.max(minW, Math.min(e.clientX - rect.left, maxAllowed));
      } else {
        calculatedWidth = Math.max(minW, Math.min(rect.right - e.clientX, maxAllowed));
      }

      setWidth(calculatedWidth);
      if (key) {
        try {
          localStorage.setItem(key, String(calculatedWidth));
        } catch {
          // ignore
        }
      }
    };

    const handleMouseUp = () => {
      setIsDragging(false);
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, [isDragging, containerRef, initialWidth]);

  return {
    width,
    setWidth,
    isDragging,
    handleMouseDown,
    resetWidth,
  };
}

// ============================================================================
// Custom Hook for Vertical Resizing (Height percentage for Top Pane)
// ============================================================================
export interface UseVerticalResizableOptions {
  initialPercent: number;
  minPercent?: number;
  maxPercent?: number;
  storageKey?: string;
  containerRef: React.RefObject<HTMLElement | null>;
}

export function useVerticalResizable({
  initialPercent,
  minPercent = 20,
  maxPercent = 80,
  storageKey,
  containerRef,
}: UseVerticalResizableOptions) {
  const [percent, setPercent] = useState<number>(() => {
    if (storageKey) {
      try {
        const stored = localStorage.getItem(storageKey);
        if (stored) {
          const val = Number(stored);
          if (!isNaN(val) && val >= minPercent && val <= maxPercent) {
            return val;
          }
        }
      } catch {
        // ignore
      }
    }
    return initialPercent;
  });

  const [isDragging, setIsDragging] = useState(false);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const resetPercent = useCallback(() => {
    setPercent(initialPercent);
    if (storageKey) {
      try {
        localStorage.removeItem(storageKey);
      } catch {
        // ignore
      }
    }
  }, [initialPercent, storageKey]);

  useEffect(() => {
    if (!isDragging) return;

    const handleMouseMove = (e: MouseEvent) => {
      if (!containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const offsetY = e.clientY - rect.top;
      const calculated = Math.max(
        minPercent,
        Math.min((offsetY / rect.height) * 100, maxPercent)
      );

      setPercent(calculated);
      if (storageKey) {
        try {
          localStorage.setItem(storageKey, String(calculated));
        } catch {
          // ignore
        }
      }
    };

    const handleMouseUp = () => {
      setIsDragging(false);
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, [isDragging, containerRef, minPercent, maxPercent, storageKey]);

  return {
    percent,
    setPercent,
    isDragging,
    handleMouseDown,
    resetPercent,
  };
}
