import { useMemo, useState, useCallback } from "react";
import type { Vault } from "@/types/vault";

export interface UseVirtualVaultListOptions {
  rowHeight?: number;
  estimateSize?: (index: number, vault: Vault) => number;
  overscan?: number;
}

export interface VirtualVaultItem {
  vault: Vault;
  index: number;
  offsetTop: number;
  size: number;
}

export function useVirtualVaultList(
  vaults: Vault[],
  options: UseVirtualVaultListOptions = {}
) {
  const { rowHeight = 72, estimateSize, overscan = 8 } = options;
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(650);

  const { items, totalSize, sizes, offsets } = useMemo(() => {
    const sizes: number[] = [];
    const offsets: number[] = [];
    let acc = 0;

    const mapped: VirtualVaultItem[] = vaults.map((vault, index) => {
      const size = estimateSize ? estimateSize(index, vault) : rowHeight;
      sizes.push(size);
      offsets.push(acc);
      const item: VirtualVaultItem = {
        vault,
        index,
        offsetTop: acc,
        size,
      };
      acc += size;
      return item;
    });

    return { items: mapped, totalSize: acc, sizes, offsets };
  }, [vaults, rowHeight, estimateSize]);

  const { startIndex, endIndex } = useMemo(() => {
    let start = 0;
    let end = vaults.length - 1;

    for (let i = 0; i < offsets.length; i++) {
      const bottom = offsets[i] + sizes[i];
      if (bottom >= scrollTop) {
        start = Math.max(0, i - overscan);
        break;
      }
    }

    let acc = 0;
    for (let i = 0; i < sizes.length; i++) {
      acc += sizes[i];
      if (acc >= scrollTop + viewportHeight) {
        end = Math.min(vaults.length - 1, i + overscan);
        break;
      }
    }

    return { startIndex: start, endIndex: end };
  }, [scrollTop, viewportHeight, vaults.length, overscan, sizes, offsets]);

  const visibleItems = items.slice(startIndex, endIndex + 1);

  const handleScroll = useCallback((event: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(event.currentTarget.scrollTop);
  }, []);

  return {
    items: visibleItems,
    totalSize,
    handleScroll,
    viewportHeight,
    setViewportHeight,
    startIndex,
    endIndex,
  };
}
