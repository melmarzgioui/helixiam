/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody } from "../components/Page";
import { Button } from "../components/Button";
import { Badge } from "../components/Badge";
import { Alert } from "../components/Alert";
import { Spinner } from "../components/Spinner";
import { EmptyState } from "../components/EmptyState";
import { Modal, ConfirmDialog } from "../components/Modal";
import { RowMenu, type RowMenuItem } from "../components/RowMenu";
import { CopyButton } from "../components/CopyButton";
import { FormField, Input, Select, Textarea } from "../components/FormField";
import { Checkbox } from "../components/Choice";
import { useToast } from "../components/ToastProvider";
import { RealmKey, RealmKeyApi } from "../api/keys";
import { useT } from "../i18n/LocaleContext";
import {
  ALGORITHMS,
  type Errors,
  canActivate,
  canAttachCertificate,
  canRetire,
  csrFileName,
  daysUntil,
  durationParts,
  expiryTone,
  fieldErrorsFromServer,
  keyLabel,
  shortFingerprint,
  splitDnsNames,
  stagingState,
  statusLabelKey,
  statusTone,
  validateCertificate,
  validateCsr,
  validateImport,
} from "./realmKeys";

export interface RealmKeysPageProps {
  api: RealmKeyApi;
  realmId: string;
}

type Dialog =
  | { kind: "import" }
  | { kind: "csr" }
  | { kind: "csrResult"; key: RealmKey; csrPem: string }
  | { kind: "certificate"; key: RealmKey }
  | { kind: "activate"; key: RealmKey }
  | { kind: "rotate" }
  | { kind: "retire"; key: RealmKey }
  | { kind: "publicKey"; key: RealmKey }
  | null;

/**
 * Realm signing keys: the ACTIVE key signs every token (and SAML assertion) of the realm; PENDING keys are published
 * (JWKS and SAML metadata) so relying parties pick them up before they sign; retained (ROTATED) keys keep verifying
 * what they signed until retired. Admins can import their own key + certificate, have the server generate a key and
 * a CSR (the private key never leaves the server), attach the CA-signed certificate, and activate when ready. Only
 * public material is ever shown, and key ids appear only in the muted technical line.
 */
export function RealmKeysPage({ api, realmId }: RealmKeysPageProps) {
  const { t, locale } = useT();
  const toast = useToast();
  const [keys, setKeys] = React.useState<RealmKey[] | null>(null);
  const [dialog, setDialog] = React.useState<Dialog>(null);
  // Changing keys needs realm-admin (the server enforces it); without it the page is read-only.
  const [canManage, setCanManage] = React.useState(false);

  const reload = React.useCallback(() => {
    setKeys(null);
    api.access(realmId).then((a) => setCanManage(!!a.canManage)).catch(() => setCanManage(false));
    api.list(realmId)
      .then(setKeys)
      .catch((e) => { setKeys([]); toast.show({ tone: "error", title: t("realmKeys.toast.loadError"), message: String(e.message ?? e) }); });
  }, [api, realmId]);
  React.useEffect(reload, [reload]);

  const fail = (title: string) => (e: unknown) =>
    toast.show({ tone: "error", title, message: String((e as Error)?.message ?? e) });
  const close = () => setDialog(null);

  const label = (k: RealmKey) => {
    const l = keyLabel(k, locale);
    return l.kind === "cn" ? l.name : t("realmKeys.label.generated", { algorithm: l.algorithm, date: l.date });
  };
  const fmtDate = (ms: number | null | undefined) => (ms
    ? new Intl.DateTimeFormat(locale === "nl" ? "nl-NL" : "en-GB", { dateStyle: "medium", timeZone: "UTC" }).format(new Date(ms))
    : "—");

  const doRetire = (key: RealmKey) => {
    close();
    api.retire(realmId, key.keyId)
      .then(() => { toast.show({ tone: "success", title: t("realmKeys.toast.retired"), message: t("realmKeys.toast.retired.message") }); reload(); })
      .catch(fail(t("realmKeys.toast.retireFailed")));
  };
  const doActivate = (key: RealmKey, force: boolean) => {
    close();
    api.activate(realmId, key.keyId, force)
      .then(() => { toast.show({ tone: "success", title: t("realmKeys.toast.activated"), message: t("realmKeys.toast.activated.message", { name: label(key) }) }); reload(); })
      .catch(fail(t("realmKeys.toast.activateFailed")));
  };
  const downloadCsr = (key: RealmKey) => {
    api.csr(realmId, key.keyId)
      .then((pem) => download(csrFileName(key.certificate?.subject ?? ""), pem))
      .catch(fail(t("realmKeys.toast.csrFailed")));
  };

  const menu = (k: RealmKey): RowMenuItem[] => {
    const items: RowMenuItem[] = [];
    if (!canManage) {
      if (k.hasCsr) items.push({ label: t("realmKeys.action.downloadCsr"), onSelect: () => downloadCsr(k) });
      if (k.publicKey) items.push({ label: t("realmKeys.action.view"), onSelect: () => setDialog({ kind: "publicKey", key: k }) });
      return items;
    }
    if (canActivate(k)) items.push({ label: t("realmKeys.action.activate"), onSelect: () => setDialog({ kind: "activate", key: k }) });
    if (canAttachCertificate(k)) items.push({ label: t("realmKeys.action.uploadCertificate"), onSelect: () => setDialog({ kind: "certificate", key: k }) });
    if (k.hasCsr) items.push({ label: t("realmKeys.action.downloadCsr"), onSelect: () => downloadCsr(k) });
    if (k.publicKey) items.push({ label: t("realmKeys.action.view"), onSelect: () => setDialog({ kind: "publicKey", key: k }) });
    if (canRetire(k)) items.push({ label: t("realmKeys.action.retire"), danger: true, onSelect: () => setDialog({ kind: "retire", key: k }) });
    return items;
  };

  const live = (keys ?? []).filter((k) => k.status === "ACTIVE" || k.status === "PENDING");
  const expired = live.filter((k) => k.certificate?.expiry === "EXPIRED");
  const expiring = live.filter((k) => k.certificate?.expiry === "EXPIRING");

  const statusBadge = (k: RealmKey) => <Badge tone={statusTone(k.status)}>{t(statusLabelKey(k.status))}</Badge>;
  const expiryCell = (k: RealmKey) => {
    if (!k.certificate) return <span className="hx-faint">—</span>;
    const tone = expiryTone(k.certificate);
    const days = daysUntil(k.certificate.notAfter);
    return (
      <span className="hx-badges">
        {fmtDate(k.certificate.notAfter)}
        {tone && <Badge tone={tone}>{tone === "danger" ? t("realmKeys.expiry.expired") : t("realmKeys.expiry.days", { days })}</Badge>}
      </span>
    );
  };
  const certificateCell = (k: RealmKey) => k.certificate ? (
    <span className="hx-stack-tight">
      <span className="hx-wrap-anywhere">{k.certificate.subject}</span>
      <span className="hx-faint hx-wrap-anywhere">{k.certificate.selfSigned ? t("realmKeys.cert.selfSigned") : t("realmKeys.cert.issuedBy", { issuer: k.certificate.issuer })}</span>
    </span>
  ) : <span className="hx-faint">{t("realmKeys.cert.none")}</span>;
  const fingerprint = (k: RealmKey) => k.certificate?.sha256Fingerprint ?? k.publicKeyFingerprint ?? "";
  const fingerprintCell = (k: RealmKey) => {
    const fp = fingerprint(k);
    if (!fp) return <span className="hx-faint">—</span>;
    return (
      <span className="hx-badges hx-nowrap">
        <span className="hx-mono hx-faint hx-fingerprint" title={fp}>{shortFingerprint(fp)}</span>
        <CopyButton value={fp} label={t("realmKeys.fingerprint.copy")} size={26} />
      </span>
    );
  };
  const technical = (k: RealmKey) => (
    <span className="hx-mono hx-faint hx-wrap-anywhere hx-keyid">{`kid ${k.kid ?? "—"} · ${t("realmKeys.keyId")} ${k.keyId}`}</span>
  );

  return (
    <Page>
      <PageHeader
        title={t("realmKeys.title")}
        description={t("realmKeys.description", { realmId })}
        actions={<>
          <Button variant="ghost" onClick={reload} disabled={keys === null}>{t("realmKeys.action.refresh")}</Button>
          {canManage && <>
            <Button variant="ghost" onClick={() => setDialog({ kind: "csr" })} disabled={keys === null}>{t("realmKeys.action.csr")}</Button>
            <Button variant="ghost" onClick={() => setDialog({ kind: "import" })} disabled={keys === null}>{t("realmKeys.action.import")}</Button>
            <Button variant="primary" onClick={() => setDialog({ kind: "rotate" })} disabled={keys === null}>{t("realmKeys.action.rotate")}</Button>
          </>}
        </>}
      />

      <PageBody>
        {keys !== null && !canManage && <Alert tone="info">{t("realmKeys.readOnly")}</Alert>}
        {expired.length > 0 && (
          <Alert tone="danger" title={t("realmKeys.alert.expired.title")}>{t("realmKeys.alert.expired.body", { names: expired.map(label).join(", ") })}</Alert>
        )}
        {expiring.length > 0 && (
          <Alert tone="warning" title={t("realmKeys.alert.expiring.title")}>{t("realmKeys.alert.expiring.body", { names: expiring.map(label).join(", ") })}</Alert>
        )}
        {keys === null ? (
          <div className="hx-loadwrap"><Spinner size={28} label={t("realmKeys.loading")} /></div>
        ) : keys.length === 0 ? (
          <EmptyState title={t("realmKeys.empty.title")} message={t("realmKeys.empty.message")} />
        ) : (
          <>
            <div className="hx-card hx-show-desktop">
              <div className="hx-tablescroll">
                <table className="hx-table">
                  <thead>
                    <tr>
                      <th>{t("realmKeys.col.key")}</th><th>{t("realmKeys.col.status")}</th><th>{t("realmKeys.col.algorithm")}</th>
                      <th>{t("realmKeys.col.certificate")}</th><th>{t("realmKeys.col.expires")}</th><th>{t("realmKeys.col.fingerprint")}</th>
                      <th className="hx-col-actions" aria-label={t("realmKeys.col.actions")} />
                    </tr>
                  </thead>
                  <tbody>
                    {keys.map((k) => (
                      <tr key={k.keyId}>
                        <td>
                          <span className="hx-stack-tight">
                            <span className="hx-namecell">{label(k)}</span>
                            <span className="hx-faint">{t(`realmKeys.source.${k.source ?? "GENERATED"}`)} · {t("realmKeys.created", { date: fmtDate(k.createdAt) })}</span>
                            {technical(k)}
                          </span>
                        </td>
                        <td>{statusBadge(k)}</td>
                        <td>{k.algorithm}</td>
                        <td>{certificateCell(k)}</td>
                        <td>{expiryCell(k)}</td>
                        <td>{fingerprintCell(k)}</td>
                        <td className="hx-cell-right">{menu(k).length > 0 && <RowMenu items={menu(k)} ariaLabel={t("realmKeys.col.actions")} />}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="hx-cards hx-show-mobile">
              {keys.map((k) => (
                <div className="hx-rowcard" key={k.keyId}>
                  <div className="hx-rowcard__head">
                    <div className="hx-rowcard__grow">
                      <div className="hx-rowcard__title hx-namecell">{statusBadge(k)}{label(k)}</div>
                      <div className="hx-rowcard__sub">{technical(k)}</div>
                    </div>
                    <div className="hx-rowcard__actions">
                      {menu(k).length > 0 && <RowMenu items={menu(k)} ariaLabel={t("realmKeys.col.actions")} />}
                    </div>
                  </div>
                  <div className="hx-rowcard__fields">
                    <div className="hx-rowcard__field"><span className="hx-rowcard__label">{t("realmKeys.col.algorithm")}</span><span className="hx-rowcard__value">{k.algorithm}</span></div>
                    <div className="hx-rowcard__field"><span className="hx-rowcard__label">{t("realmKeys.col.certificate")}</span><span className="hx-rowcard__value">{certificateCell(k)}</span></div>
                    <div className="hx-rowcard__field"><span className="hx-rowcard__label">{t("realmKeys.col.expires")}</span><span className="hx-rowcard__value">{expiryCell(k)}</span></div>
                    <div className="hx-rowcard__field"><span className="hx-rowcard__label">{t("realmKeys.col.fingerprint")}</span><span className="hx-rowcard__value">{fingerprintCell(k)}</span></div>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </PageBody>

      {dialog?.kind === "import" && (
        <ImportDialog onClose={close} onSubmit={(body) => api.importKey(realmId, body).then((k) => {
          close();
          toast.show({ tone: "success", title: t("realmKeys.toast.imported"), message: t("realmKeys.toast.imported.message", { name: label(k) }) });
          reload();
        })} />
      )}
      {dialog?.kind === "csr" && (
        <CsrDialog onClose={close} onSubmit={(body) => api.createCsr(realmId, body).then((r) => {
          setDialog({ kind: "csrResult", key: r.key, csrPem: r.csrPem });
          reload();
        })} />
      )}
      {dialog?.kind === "csrResult" && (
        <Modal open title={t("realmKeys.csr.result.title")} onClose={close} width={640}
          footer={<div className="hx-formactions hx-formactions--end">
            <Button variant="ghost" onClick={() => download(csrFileName(dialog.key.certificate?.subject ?? ""), dialog.csrPem)}>{t("realmKeys.csr.download")}</Button>
            <Button variant="primary" onClick={close}>{t("realmKeys.done")}</Button>
          </div>}>
          <div className="hx-stackgap">
            <p className="hx-help">{t("realmKeys.csr.result.body")}</p>
            <div className="hx-badges"><CopyButton value={dialog.csrPem} label={t("realmKeys.csr.copy")} /></div>
            <pre className="hx-codeblock">{dialog.csrPem}</pre>
          </div>
        </Modal>
      )}
      {dialog?.kind === "certificate" && (
        <CertificateDialog keyName={label(dialog.key)} active={dialog.key.status === "ACTIVE"} onClose={close}
          onSubmit={(pem) => api.attachCertificate(realmId, dialog.key.keyId, pem).then(() => {
            close();
            toast.show({ tone: "success", title: t("realmKeys.toast.certificate"), message: t("realmKeys.toast.certificate.message") });
            reload();
          })} />
      )}
      {dialog?.kind === "activate" && (
        <ActivateDialog keyName={label(dialog.key)} realmKey={dialog.key} onClose={close}
          onActivate={(force) => doActivate(dialog.key, force)} />
      )}
      {dialog?.kind === "rotate" && <RotateDialog onClose={close} onSubmit={(algorithm) => api.rotate(realmId, algorithm).then(() => {
        close();
        toast.show({ tone: "success", title: t("realmKeys.toast.rotated"), message: t("realmKeys.toast.rotated.done") });
        reload();
      })} />}
      <ConfirmDialog
        open={dialog?.kind === "retire"}
        title={t("realmKeys.confirm.retire.title")}
        message={dialog?.kind === "retire" ? t(dialog.key.status === "PENDING" ? "realmKeys.confirm.retire.pending"
          : dialog.key.status === "ACTIVE" ? "realmKeys.confirm.retire.activeEc" : "realmKeys.confirm.retire.message.named",
          { name: label(dialog.key) }) : ""}
        confirmLabel={t("realmKeys.confirm.retire.label")}
        cancelLabel={t("realmKeys.cancel")}
        onConfirm={() => dialog?.kind === "retire" && doRetire(dialog.key)}
        onCancel={close}
      />
      <Modal open={dialog?.kind === "publicKey"} title={t("realmKeys.modal.publicKey.title")} onClose={close} width={620}>
        {dialog?.kind === "publicKey" && <>
          <p className="hx-help">{t("realmKeys.modal.publicKey.body", { algorithm: dialog.key.algorithm })}</p>
          <pre className="hx-codeblock">{dialog.key.publicKey}</pre>
        </>}
      </Modal>
    </Page>
  );
}

// ------------------------------------------------------------------------------------------------ dialogs

/** Shared: a form dialog whose submit validates first, then shows the server's field errors inline. */
function useFormSubmit(fields: string[]) {
  const [errors, setErrors] = React.useState<Errors>({});
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState<string | null>(null);
  const run = (local: Errors, action: () => Promise<unknown>) => {
    setErrors(local);
    setMessage(null);
    if (Object.keys(local).length > 0) return;
    setBusy(true);
    action()
      .catch((e) => {
        const server = fieldErrorsFromServer(e, fields);
        setErrors(server);
        if (Object.keys(server).length === 0) setMessage(String((e as Error)?.message ?? e));
      })
      .finally(() => setBusy(false));
  };
  return { errors, busy, message, run };
}

function ImportDialog({ onClose, onSubmit }: { onClose: () => void; onSubmit: (b: { privateKeyPem: string; certificateChainPem: string }) => Promise<unknown> }) {
  const { t } = useT();
  const [form, setForm] = React.useState({ privateKeyPem: "", certificateChainPem: "" });
  const f = useFormSubmit(["privateKeyPem", "certificateChainPem"]);
  return (
    <Modal open title={t("realmKeys.import.title")} onClose={onClose} width={680}
      footer={<div className="hx-formactions hx-formactions--end">
        <Button variant="ghost" onClick={onClose}>{t("realmKeys.cancel")}</Button>
        <Button variant="primary" disabled={f.busy} onClick={() => f.run(validateImport(form), () => onSubmit(form))}>{t("realmKeys.import.submit")}</Button>
      </div>}>
      <div className="hx-stackgap">
        <p className="hx-help">{t("realmKeys.import.body")}</p>
        {f.message && <Alert tone="danger">{f.message}</Alert>}
        <FormField label={t("realmKeys.import.key")} hint={t("realmKeys.import.keyHint")} required error={f.errors.privateKeyPem && t(f.errors.privateKeyPem)}>
          <Textarea rows={6} className="hx-mono" spellCheck={false} autoComplete="off" value={form.privateKeyPem}
            onChange={(e) => setForm({ ...form, privateKeyPem: e.target.value })} placeholder="-----BEGIN PRIVATE KEY-----" />
        </FormField>
        <FormField label={t("realmKeys.import.chain")} hint={t("realmKeys.import.chainHint")} required error={f.errors.certificateChainPem && t(f.errors.certificateChainPem)}>
          <Textarea rows={6} className="hx-mono" spellCheck={false} value={form.certificateChainPem}
            onChange={(e) => setForm({ ...form, certificateChainPem: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----" />
        </FormField>
      </div>
    </Modal>
  );
}

function CsrDialog({ onClose, onSubmit }: { onClose: () => void; onSubmit: (b: { algorithm: string; subject: string; dnsNames: string[] }) => Promise<unknown> }) {
  const { t } = useT();
  const [form, setForm] = React.useState({ algorithm: "RS256", subject: "", dnsNames: "" });
  const f = useFormSubmit(["algorithm", "subject", "dnsNames"]);
  return (
    <Modal open title={t("realmKeys.csr.title")} onClose={onClose} width={600}
      footer={<div className="hx-formactions hx-formactions--end">
        <Button variant="ghost" onClick={onClose}>{t("realmKeys.cancel")}</Button>
        <Button variant="primary" disabled={f.busy} onClick={() => f.run(validateCsr(form),
          () => onSubmit({ algorithm: form.algorithm, subject: form.subject.trim(), dnsNames: splitDnsNames(form.dnsNames) }))}>{t("realmKeys.csr.submit")}</Button>
      </div>}>
      <div className="hx-stackgap">
        <p className="hx-help">{t("realmKeys.csr.body")}</p>
        {f.message && <Alert tone="danger">{f.message}</Alert>}
        <FormField label={t("realmKeys.col.algorithm")} required error={f.errors.algorithm && t(f.errors.algorithm)}>
          <Select value={form.algorithm} onChange={(v) => setForm({ ...form, algorithm: v })}
            options={ALGORITHMS.map((a) => ({ value: a, label: t(`realmKeys.alg.${a}`) }))} />
        </FormField>
        {form.algorithm === "ES256" && <Alert tone="warning" title={t("realmKeys.ec.title")}>{t("realmKeys.ec.body")}</Alert>}
        <FormField label={t("realmKeys.csr.subject")} hint={t("realmKeys.csr.subjectHint")} required error={f.errors.subject && t(f.errors.subject)}>
          <Input value={form.subject} onChange={(e) => setForm({ ...form, subject: e.target.value })} placeholder="CN=idp.example.com, O=Example, C=NL" />
        </FormField>
        <FormField label={t("realmKeys.csr.dns")} hint={t("realmKeys.csr.dnsHint")} error={f.errors.dnsNames && t(f.errors.dnsNames)}>
          <Input value={form.dnsNames} onChange={(e) => setForm({ ...form, dnsNames: e.target.value })} placeholder="idp.example.com" />
        </FormField>
      </div>
    </Modal>
  );
}

function CertificateDialog({ keyName, active, onClose, onSubmit }: { keyName: string; active: boolean; onClose: () => void; onSubmit: (pem: string) => Promise<unknown> }) {
  const { t } = useT();
  const [pem, setPem] = React.useState("");
  const f = useFormSubmit(["certificateChainPem"]);
  return (
    <Modal open title={t("realmKeys.cert.title")} onClose={onClose} width={640}
      footer={<div className="hx-formactions hx-formactions--end">
        <Button variant="ghost" onClick={onClose}>{t("realmKeys.cancel")}</Button>
        <Button variant="primary" disabled={f.busy} onClick={() => f.run(validateCertificate({ certificateChainPem: pem }), () => onSubmit(pem))}>{t("realmKeys.cert.submit")}</Button>
      </div>}>
      <div className="hx-stackgap">
        <p className="hx-help">{t("realmKeys.cert.body", { name: keyName })}</p>
        {active && <Alert tone="warning">{t("realmKeys.cert.activeWarning")}</Alert>}
        {f.message && <Alert tone="danger">{f.message}</Alert>}
        <FormField label={t("realmKeys.import.chain")} hint={t("realmKeys.import.chainHint")} required error={f.errors.certificateChainPem && t(f.errors.certificateChainPem)}>
          <Textarea rows={8} className="hx-mono" spellCheck={false} value={pem} onChange={(e) => setPem(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
        </FormField>
      </div>
    </Modal>
  );
}

function ActivateDialog({ keyName, realmKey, onClose, onActivate }: { keyName: string; realmKey: RealmKey; onClose: () => void; onActivate: (force: boolean) => void }) {
  const { t } = useT();
  const staging = stagingState(realmKey);
  const [force, setForce] = React.useState(false);
  const expired = realmKey.certificate?.expiry === "EXPIRED";
  const blocked = !staging.ready && !force;
  const duration = (minutes: number) => { const d = durationParts(minutes); return t(d.key, { count: d.count }); };
  return (
    <Modal open title={t("realmKeys.confirm.activate.title")} onClose={onClose} width={600}
      footer={<div className="hx-formactions hx-formactions--end">
        <Button variant="ghost" onClick={onClose}>{t("realmKeys.cancel")}</Button>
        <Button variant="primary" disabled={blocked} onClick={() => onActivate(!staging.ready)}>{t("realmKeys.confirm.activate.label")}</Button>
      </div>}>
      <div className="hx-stackgap">
        <p>{t("realmKeys.confirm.activate.now", { name: keyName, age: duration(staging.publishedMinutes) })}</p>
        <p>{t(realmKey.algorithm === "ES256" ? "realmKeys.confirm.activate.messageEc" : "realmKeys.confirm.activate.message", { name: keyName })}</p>
        {expired && <Alert tone="danger" title={t("realmKeys.confirm.activate.expiredTitle")}>{t("realmKeys.confirm.activate.expired")}</Alert>}
        {!staging.ready && (
          <Alert tone="warning" title={t("realmKeys.confirm.activate.stagingTitle")}>
            <div className="hx-stackgap">
              <span>{t("realmKeys.confirm.activate.staging", { wait: duration(staging.waitMinutes) })}</span>
              <Checkbox label={t("realmKeys.confirm.activate.force")} checked={force} onChange={setForce} />
            </div>
          </Alert>
        )}
        <Alert tone="warning" title={t("realmKeys.confirm.activate.samlTitle")}>{t("realmKeys.confirm.activate.saml")}</Alert>
        {realmKey.algorithm === "ES256" && <Alert tone="warning" title={t("realmKeys.ec.title")}>{t("realmKeys.ec.body")}</Alert>}
        {!realmKey.certificate && <Alert tone="info">{t("realmKeys.confirm.activate.noCert")}</Alert>}
      </div>
    </Modal>
  );
}

function RotateDialog({ onClose, onSubmit }: { onClose: () => void; onSubmit: (algorithm: string) => Promise<unknown> }) {
  const { t } = useT();
  const [algorithm, setAlgorithm] = React.useState("RS256");
  const f = useFormSubmit(["algorithm"]);
  return (
    <Modal open title={t("realmKeys.confirm.rotate.title")} onClose={onClose} width={560}
      footer={<div className="hx-formactions hx-formactions--end">
        <Button variant="ghost" onClick={onClose}>{t("realmKeys.cancel")}</Button>
        <Button variant="primary" disabled={f.busy} onClick={() => f.run(
          (ALGORITHMS as readonly string[]).includes(algorithm) ? {} : { algorithm: "realmKeys.v.algorithm" },
          () => onSubmit(algorithm))}>{t("realmKeys.confirm.rotate.label")}</Button>
      </div>}>
      <div className="hx-stackgap">
        <p>{t("realmKeys.confirm.rotate.message")}</p>
        {f.message && <Alert tone="danger">{f.message}</Alert>}
        <FormField label={t("realmKeys.col.algorithm")} required error={f.errors.algorithm && t(f.errors.algorithm)}>
          <Select value={algorithm} onChange={setAlgorithm} options={ALGORITHMS.map((a) => ({ value: a, label: t(`realmKeys.alg.${a}`) }))} />
        </FormField>
        <Alert tone="warning" title={t("realmKeys.confirm.activate.samlTitle")}>{t("realmKeys.confirm.rotate.saml")}</Alert>
        {algorithm === "ES256" && <Alert tone="warning" title={t("realmKeys.ec.title")}>{t("realmKeys.ec.body")}</Alert>}
      </div>
    </Modal>
  );
}

function download(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/pkcs10" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
