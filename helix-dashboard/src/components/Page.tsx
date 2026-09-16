import React from "react";

/**
 * Canonical page layout kit. EVERY console page derives from these so pages share one structure, rhythm
 * and spacing. All class-based (see page.css) — pages should not inline-style layout.
 *
 *   <Page>
 *     <PageHeader title="…" description="…" actions={<Button/>} />
 *     <PageBody>            // vertical stack with the canonical --stack-gap
 *       <Section title="…">…</Section>
 *       <Card>…</Card>
 *     </PageBody>
 *   </Page>
 */

export interface PageProps {
  children: React.ReactNode;
}
/** Outermost page wrapper — owns the page's max width/padding rhythm. */
export function Page({ children }: PageProps) {
  return <div className="hx-page">{children}</div>;
}

export interface PageHeaderProps {
  title: React.ReactNode;
  description?: React.ReactNode;
  /** Right-aligned primary actions (e.g. a "Create" button). */
  actions?: React.ReactNode;
}
/** Standard page title block — h1 + one-line description + optional actions. */
export function PageHeader({ title, description, actions }: PageHeaderProps) {
  return (
    <div className="hx-pagehead">
      <div className="hx-pagehead__text">
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {actions && <div className="hx-pagehead__actions">{actions}</div>}
    </div>
  );
}

export interface PageBodyProps {
  children: React.ReactNode;
  /** `grid` lays children out in the responsive detail grid; default is a vertical stack. */
  layout?: "stack" | "grid";
}
/** Content region below the header — a uniform vertical stack (or responsive grid) of sections/cards. */
export function PageBody({ children, layout = "stack" }: PageBodyProps) {
  return <div className={layout === "grid" ? "hx-detailgrid" : "hx-pagebody"}>{children}</div>;
}

export interface SectionProps {
  title?: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  /** `cols` flows fields side-by-side to fill width; default is a single column. */
  layout?: "single" | "cols";
  children?: React.ReactNode;
}
/** Titled content card with a header strip + padded body — the workhorse container for a page. */
export function Section({ title, description, actions, layout = "single", children }: SectionProps) {
  return (
    <section className="hx-card hx-section">
      {(title || actions) && (
        <header className="hx-section__head">
          <div>
            {title && <h2>{title}</h2>}
            {description && <p>{description}</p>}
          </div>
          {actions && <div className="hx-section__headctl">{actions}</div>}
        </header>
      )}
      <div className={layout === "cols" ? "hx-section__body hx-section__body--cols" : "hx-section__body"}>{children}</div>
    </section>
  );
}

export interface PageToolbarProps {
  children: React.ReactNode;
}
/** A horizontal control strip (search, filters, buttons) that sits above a table/list. */
export function PageToolbar({ children }: PageToolbarProps) {
  return <div className="hx-toolbar">{children}</div>;
}
