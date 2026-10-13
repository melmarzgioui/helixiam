/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";

export interface Column<T> {
  key: string;
  header: React.ReactNode;
  render?: (row: T) => React.ReactNode;
  width?: string;
  align?: "left" | "right";
}

export interface TableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  empty?: React.ReactNode;
}

/** Data table — connections, users, sessions. Hairline rows, hover highlight (kit's .hx-table). */
export function Table<T>({ columns, rows, rowKey, onRowClick, empty }: TableProps<T>) {
  return (
    <div className="hx-tablescroll hx-tablescroll--boxed">
      <table className="hx-table">
        <thead>
          <tr>
            {columns.map((c) => (
              <th
                key={c.key}
                className={c.align === "right" ? "hx-cell-right" : undefined}
                // A per-column width is author-supplied and open-ended (not a fixed set of sizes a
                // class could enumerate), so it's carried as a custom property, never a literal style.
                style={c.width ? ({ "--colw": c.width } as React.CSSProperties) : undefined}
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="hx-table__empty">
                {empty ?? "No rows."}
              </td>
            </tr>
          )}
          {rows.map((row) => {
            const k = rowKey(row);
            return (
              <tr
                key={k}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                className={onRowClick ? "hx-row-clickable" : undefined}
              >
                {columns.map((c) => (
                  <td key={c.key} className={c.align === "right" ? "hx-cell-right" : undefined}>
                    {c.render ? c.render(row) : (row as Record<string, React.ReactNode>)[c.key]}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
