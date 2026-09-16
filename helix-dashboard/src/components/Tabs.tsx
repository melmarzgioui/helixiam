import React from "react";

export interface TabItem {
  id: string;
  label: string;
}

export interface TabsProps {
  tabs: TabItem[];
  value?: string;
  defaultValue?: string;
  onChange?: (id: string) => void;
}

/** Underline tabs — connection detail sections (Settings / Mappers / Metadata). */
export function Tabs({ tabs, value, defaultValue, onChange }: TabsProps) {
  const isControlled = value !== undefined;
  const [internal, setInternal] = React.useState(defaultValue ?? tabs[0]?.id);
  const active = isControlled ? value : internal;

  const select = (id: string) => {
    if (!isControlled) setInternal(id);
    onChange?.(id);
  };

  return (
    <div role="tablist" className="hx-tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" className="hx-tab" aria-selected={t.id === active} onClick={() => select(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}
