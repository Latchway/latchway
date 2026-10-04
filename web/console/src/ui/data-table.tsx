import type { KeyboardEvent, ReactNode } from "react";

import { cx } from "./cx";
import { Icon } from "./icon";

export interface Column<Row> {
  align?: "left" | "right";
  header: ReactNode;
  key: string;
  render: (row: Row) => ReactNode;
  sortable?: boolean;
  width?: number | string;
}

export interface SortState {
  dir: "asc" | "desc";
  key: string;
}

interface DataTableProps<Row> {
  caption: string;
  className?: string;
  columns: readonly Column<Row>[];
  dense?: boolean;
  onSelect?: (row: Row) => void;
  onSort?: (key: string) => void;
  rowKey: (row: Row) => string;
  rows: readonly Row[];
  selectedKey?: string;
  sort?: SortState;
}

/** Galva table. Selectable rows are focusable and open with Enter or Space. */
export function DataTable<Row>({ caption, className, columns, dense, onSelect, onSort, rowKey, rows, selectedKey, sort }: DataTableProps<Row>) {
  function onRowKeyDown(event: KeyboardEvent<HTMLTableRowElement>, row: Row): void {
    if (!onSelect || event.target !== event.currentTarget) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(row);
    }
  }
  return (
    <div className={cx("lw-table-wrap", className)}>
      <table aria-label={caption} className={cx("lw-table", dense && "lw-table--dense")}>
        <thead>
          <tr>
            {columns.map((column) => {
              const sorted = sort?.key === column.key ? sort.dir : undefined;
              return (
                <th
                  aria-sort={sorted ? (sorted === "asc" ? "ascending" : "descending") : undefined}
                  className={column.align === "right" ? "lw-align-right" : undefined}
                  key={column.key}
                  scope="col"
                  style={column.width ? { width: column.width } : undefined}
                >
                  {column.sortable && onSort ? (
                    <button className="lw-sort" onClick={() => onSort(column.key)} type="button">
                      {column.header}
                      <Icon name={sorted === "asc" ? "arrowUp" : sorted === "desc" ? "arrowDown" : "sort"} />
                    </button>
                  ) : column.header}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const key = rowKey(row);
            return (
              <tr
                aria-selected={onSelect ? selectedKey === key : undefined}
                data-clickable={onSelect ? "" : undefined}
                key={key}
                onClick={onSelect ? () => onSelect(row) : undefined}
                onKeyDown={onSelect ? (event) => onRowKeyDown(event, row) : undefined}
                tabIndex={onSelect ? 0 : undefined}
              >
                {columns.map((column) => <td className={column.align === "right" ? "lw-align-right" : undefined} key={column.key}>{column.render(row)}</td>)}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
