/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Section } from "../components/Page";
import { Button } from "../components/Button";
import { Alert } from "../components/Alert";
import { FormField, Select } from "../components/FormField";
import { useToast } from "../components/ToastProvider";
import type { RealmKeyApi } from "../api/keys";
import { useT } from "../i18n/LocaleContext";
import { DEFAULT_ALGS, SAML_ALGS, fieldErrorsFromServer, validateSigningSettings, type Errors } from "./realmKeys";

/**
 * Realm settings → Tokens → Signing: which algorithm access tokens (and logout, delegation, workload-identity tokens
 * and JARM) are signed with, and which key signs SAML. ID tokens follow each client's own setting. Only algorithms
 * the realm has an ACTIVE key for can be chosen.
 */
export function SigningSettingsSection({ api, realmId }: { api: RealmKeyApi; realmId: string }) {
  const { t } = useT();
  const toast = useToast();
  const [form, setForm] = React.useState<{ defaultAlg: string; samlAlg: string } | null>(null);
  const [active, setActive] = React.useState<string[]>([]);
  const [errors, setErrors] = React.useState<Errors>({});
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    api.signingSettings(realmId)
      .then((s) => { setForm({ defaultAlg: s.defaultAlg, samlAlg: s.samlAlg }); setActive(s.activeAlgorithms); })
      .catch(() => setForm(null));
  }, [api, realmId]);

  if (!form) return null;
  const save = () => {
    const local = validateSigningSettings(form, active);
    setErrors(local);
    if (Object.keys(local).length) return;
    setBusy(true);
    api.saveSigningSettings(realmId, form)
      .then((s) => { setActive(s.activeAlgorithms); toast.show({ tone: "success", title: t("signing.saved") }); })
      .catch((e) => {
        const server = fieldErrorsFromServer(e, ["defaultAlg", "samlAlg"]);
        setErrors(server);
        if (!Object.keys(server).length) toast.show({ tone: "error", title: t("signing.saveFailed"), message: String((e as Error)?.message ?? e) });
      })
      .finally(() => setBusy(false));
  };
  const option = (a: string) => ({ value: a, label: active.includes(a) ? a : t("signing.noKey", { alg: a }) });
  const err = (f: string) => errors[f] && t(errors[f]);

  return (
    <Section title={t("signing.title")} description={t("signing.description")}
      actions={<Button variant="primary" onClick={save} disabled={busy}>{t("signing.save")}</Button>}>
      <FormField label={t("signing.defaultAlg")} hint={t("signing.defaultAlg.hint")} error={err("defaultAlg")}>
        <Select aria-label={t("signing.defaultAlg")} value={form.defaultAlg} onChange={(v) => setForm({ ...form, defaultAlg: v })}
          options={DEFAULT_ALGS.map(option)} />
      </FormField>
      <FormField label={t("signing.samlAlg")} hint={t("signing.samlAlg.hint")} error={err("samlAlg")}>
        <Select aria-label={t("signing.samlAlg")} value={form.samlAlg} onChange={(v) => setForm({ ...form, samlAlg: v })}
          options={SAML_ALGS.map(option)} />
      </FormField>
      {(form.defaultAlg === "ES256" || form.samlAlg === "ES256") && (
        <Alert tone="warning" title={t("realmKeys.ec.title")}>{t("realmKeys.ec.body")}</Alert>
      )}
    </Section>
  );
}
