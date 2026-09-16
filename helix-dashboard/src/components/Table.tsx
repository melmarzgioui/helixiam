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

/** Data table — connections, users, sessions. Hairline rows, hover highlight. */
export function Table<T>({ columns, rows, rowKey, onRowClick, empty }: TableProps<T>) {
  const [hover, setHover] = React.useState<string | null>(null);
  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: "var(--r)", overflow: "hidden" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", font: "400 .92rem var(--font)" }}>
        <thead>
          <tr style={{ background: "var(--surface)" }}>
            {columns.map((c) => (
              <th
                key={c.key}
                style={{
                  textAlign: c.align ?? "left",
                  padding: ".7rem 1rem",
                  width: c.width,
                  color: "var(--fg-faint)",
                  font: "600 .76rem var(--font)",
                  letterSpacing: ".05em",
                  textTransform: "uppercase",
                  borderBottom: "1px solid var(--border)",
                }}
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td colSpan={columns.length} style={{ padding: "2rem 1rem", textAlign: "center", color: "var(--fg-faint)" }}>
                {empty ?? "No rows."}
              </td>
            </tr>
          )}
          {rows.map((row) => {
            const k = rowKey(row);
            return (
              <tr
                key={k}
                onMouseEnter={() => setHover(k)}
                onMouseLeave={() => setHover(null)}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                style={{
                  background: hover === k ? "var(--surface)" : "transparent",
                  cursor: onRowClick ? "pointer" : "default",
                  transition: "background .1s var(--ease)",
                }}
              >
                {columns.map((c) => (
                  <td
                    key={c.key}
                    style={{
                      textAlign: c.align ?? "left",
                      padding: ".75rem 1rem",
                      color: "var(--fg)",
                      borderBottom: "1px solid var(--border)",
                    }}
                  >
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
