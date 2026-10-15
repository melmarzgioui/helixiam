/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// --- a fake admin API that reproduces the real server's identity-provider persistence contract ---------
//
// IdentityProviderConfigService.saveOrUpdate (helix-iam-server): on every save, the plain (non-secret)
// config is fully replaced by whatever the write sent (an omitted plain key is gone); a secret key
// (here, accessCertificatePrivateKey) is kept from the previous save unless the write sends a new value
// or "clear<Key>": "true". IdentityProviderAdminView never returns a secret's value, only "<key>Set".

const walletSecretKey = "accessCertificatePrivateKey"

type fakeIdentityProviderServer struct {
	stored map[string]map[string]string // alias -> full config incl. the secret key
	ipMeta map[string]IdentityProviderWrite
}

func newFakeIdentityProviderServer(t *testing.T) (*httptest.Server, *fakeIdentityProviderServer) {
	t.Helper()
	f := &fakeIdentityProviderServer{stored: map[string]map[string]string{}, ipMeta: map[string]IdentityProviderWrite{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/realms/master/identity-providers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var in IdentityProviderWrite
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.save(in)
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/admin/realms/master/identity-providers/", func(w http.ResponseWriter, r *http.Request) {
		alias := r.URL.Path[len("/admin/realms/master/identity-providers/"):]
		switch r.Method {
		case http.MethodGet:
			cfg, ok := f.stored[alias]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			meta := f.ipMeta[alias]
			out := map[string]any{
				"realmId": "master", "alias": alias, "protocol": meta.Protocol,
				"displayName": meta.DisplayName, "enabled": meta.Enabled,
				"config": viewOf(cfg),
			}
			_ = json.NewEncoder(w).Encode(out)
		case http.MethodPut:
			var in IdentityProviderWrite
			_ = json.NewDecoder(r.Body).Decode(&in)
			in.Alias = alias
			f.save(in)
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			if _, ok := f.stored[alias]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(f.stored, alias)
			delete(f.ipMeta, alias)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	return httptest.NewServer(mux), f
}

// save reproduces IdentityProviderConfigService.saveOrUpdate: plain keys are fully replaced by the
// write; the secret key is kept unless the write sends a new (non-blank) value or clears it.
func (f *fakeIdentityProviderServer) save(in IdentityProviderWrite) {
	prevSecret, hadPrev := f.stored[in.Alias][walletSecretKey]
	merged := map[string]string{}
	for k, v := range in.Config {
		if k == "clear"+"AccessCertificatePrivateKey" {
			continue
		}
		merged[k] = v
	}
	if _, given := in.Config[walletSecretKey]; !given || in.Config[walletSecretKey] == "" {
		if in.Config["clearAccessCertificatePrivateKey"] != "true" && hadPrev {
			merged[walletSecretKey] = prevSecret
		} else {
			delete(merged, walletSecretKey)
		}
	}
	f.stored[in.Alias] = merged
	f.ipMeta[in.Alias] = in
}

// viewOf mirrors IdentityProviderAdminView.of: the secret key becomes "<key>Set": bool, never its value.
func viewOf(cfg map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range cfg {
		if k == walletSecretKey {
			continue
		}
		out[k] = v
	}
	_, set := cfg[walletSecretKey]
	out[walletSecretKey+"Set"] = set && cfg[walletSecretKey] != ""
	return out
}

func newWalletClient(baseURL string) *Client {
	return NewClient(baseURL, baseURL+"/realms/master", "master", "", "")
}

// --- client-level CRUD -----------------------------------------------------------------------------------

func TestIdentityProviderClient_CreateReadUpdateDelete(t *testing.T) {
	srv, _ := newFakeIdentityProviderServer(t)
	defer srv.Close()
	c := newWalletClient(srv.URL)
	ctx := context.Background()

	write := IdentityProviderWrite{
		Alias: "eudi-wallet", Protocol: "eudi-wallet", DisplayName: "EU Digital Identity Wallet", Enabled: true,
		Config: map[string]string{"accessKeyRef": "software:gov/primary", "trustAnchors": "PEM", "credentialFormats": `["dc+sd-jwt","mso_mdoc"]`},
	}
	if err := c.CreateIdentityProvider(ctx, write); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, nf, err := c.GetIdentityProvider(ctx, "eudi-wallet")
	if err != nil || nf {
		t.Fatalf("get: err=%v nf=%v", err, nf)
	}
	if got.Protocol != "eudi-wallet" || got.ConfigString("accessKeyRef") != "software:gov/primary" {
		t.Fatalf("unexpected read: %+v", got)
	}

	write.Config["accessKeyRef"] = "software:gov/secondary"
	if err := c.UpdateIdentityProvider(ctx, "eudi-wallet", write); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _, _ = c.GetIdentityProvider(ctx, "eudi-wallet")
	if got.ConfigString("accessKeyRef") != "software:gov/secondary" {
		t.Fatalf("expected updated accessKeyRef, got %q", got.ConfigString("accessKeyRef"))
	}

	if err := c.DeleteIdentityProvider(ctx, "eudi-wallet"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, nf, _ := c.GetIdentityProvider(ctx, "eudi-wallet"); !nf {
		t.Fatalf("expected not-found after delete")
	}
}

// TestIdentityProviderClient_SecretNeverReturned: the admin API never sends the dev private key back,
// only "<key>Set": true — the resource's no-perpetual-diff contract for access_certificate_private_key.
func TestIdentityProviderClient_SecretNeverReturned(t *testing.T) {
	srv, _ := newFakeIdentityProviderServer(t)
	defer srv.Close()
	c := newWalletClient(srv.URL)
	ctx := context.Background()

	write := IdentityProviderWrite{Alias: "dev-wallet", Protocol: "eudi-wallet", Enabled: true,
		Config: map[string]string{walletSecretKey: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"}}
	if err := c.CreateIdentityProvider(ctx, write); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, _, err := c.GetIdentityProvider(ctx, "dev-wallet")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, present := got.Config[walletSecretKey]; present {
		t.Fatalf("the secret value must never be returned, got %v", got.Config[walletSecretKey])
	}
	if set, _ := got.Config[walletSecretKey+"Set"].(bool); !set {
		t.Fatalf("expected %sSet=true", walletSecretKey)
	}

	// Updating an unrelated field without resending the secret must keep it stored (server contract).
	if err := c.UpdateIdentityProvider(ctx, "dev-wallet", IdentityProviderWrite{
		Alias: "dev-wallet", Protocol: "eudi-wallet", Enabled: true, Config: map[string]string{"clientIdHost": "verifier.example"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _, _ = c.GetIdentityProvider(ctx, "dev-wallet")
	if set, _ := got.Config[walletSecretKey+"Set"].(bool); !set {
		t.Fatalf("secret should still be set after an update that did not touch it")
	}
}

// --- model <-> wire (pure, no server) --------------------------------------------------------------------

func TestToWrite_OmitsUnsetAttributes(t *testing.T) {
	ctx := context.Background()
	m := walletIdentityProviderModel{
		Alias:        types.StringValue("eudi-wallet"),
		DisplayName:  types.StringValue("Wallet"),
		Enabled:      types.BoolNull(), // unset -> defaults to true client-side
		AccessKeyRef: types.StringValue("software:gov/primary"),
		// everything else left as the Go zero value, i.e. types.String{}/types.List{} (null-equivalent)
	}
	w := m.toWrite(ctx)
	if !w.Enabled {
		t.Fatalf("expected enabled to default true")
	}
	if w.Protocol != walletProtocol {
		t.Fatalf("expected protocol %q, got %q", walletProtocol, w.Protocol)
	}
	if _, ok := w.Config["clientIdHost"]; ok {
		t.Fatalf("unset clientIdHost must be omitted from the write, got %q", w.Config["clientIdHost"])
	}
	if _, ok := w.Config["credentialFormats"]; ok {
		t.Fatalf("unset credentialFormats must be omitted from the write")
	}
	if w.Config["accessKeyRef"] != "software:gov/primary" {
		t.Fatalf("expected accessKeyRef to be written, got %q", w.Config["accessKeyRef"])
	}
}

func TestToWrite_EncodesListsAsJSON(t *testing.T) {
	ctx := context.Background()
	formats, diags := types.ListValueFrom(ctx, types.StringType, []string{"dc+sd-jwt", "mso_mdoc"})
	if diags.HasError() {
		t.Fatalf("building list: %v", diags)
	}
	m := walletIdentityProviderModel{Alias: types.StringValue("w"), CredentialFormats: formats}
	w := m.toWrite(ctx)
	if w.Config["credentialFormats"] != `["dc+sd-jwt","mso_mdoc"]` {
		t.Fatalf("unexpected JSON encoding: %q", w.Config["credentialFormats"])
	}
}

func TestApplyRead_SparseConfigRoundTrips(t *testing.T) {
	ctx := context.Background()
	ip := &IdentityProviderRead{
		Alias: "w", Protocol: "eudi-wallet", DisplayName: "Wallet", Enabled: true,
		Config: map[string]any{
			"accessKeyRef":      "software:gov/primary",
			"credentialFormats": `["dc+sd-jwt"]`,
		},
	}
	var m walletIdentityProviderModel
	applyRead(ctx, &m, ip)

	if m.ClientIDHost.IsNull() == false {
		t.Fatalf("clientIdHost absent server-side must read back as null, got %v", m.ClientIDHost)
	}
	if m.TransactionTTLSeconds.IsNull() == false {
		t.Fatalf("transactionTtlSeconds absent server-side must read back as null, got %v", m.TransactionTTLSeconds)
	}
	var formats []string
	if diags := m.CredentialFormats.ElementsAs(ctx, &formats, false); diags.HasError() || len(formats) != 1 || formats[0] != "dc+sd-jwt" {
		t.Fatalf("unexpected credential_formats: %v (diags %v)", formats, diags)
	}
}

// TestApplyRead_NeverTouchesTheSecret is the no-perpetual-diff guarantee for
// access_certificate_private_key: Read must not null it out (the server never returns it) and must not
// require re-sending it on every apply.
func TestApplyRead_NeverTouchesTheSecret(t *testing.T) {
	ctx := context.Background()
	m := walletIdentityProviderModel{AccessCertificatePrivateKey: types.StringValue("-----BEGIN PRIVATE KEY-----\n...")}
	ip := &IdentityProviderRead{
		Alias: "dev-wallet", Protocol: "eudi-wallet", Enabled: true,
		Config: map[string]any{walletSecretKey + "Set": true}, // no "accessCertificatePrivateKey" key at all
	}
	applyRead(ctx, &m, ip)
	if m.AccessCertificatePrivateKey.ValueString() != "-----BEGIN PRIVATE KEY-----\n..." {
		t.Fatalf("the secret attribute must be left exactly as it was in state, got %q", m.AccessCertificatePrivateKey.ValueString())
	}
}

// TestApplyRead_IsIdempotent: applying the same server response twice must not change the model further
// (the drift / no-perpetual-diff case for every other attribute).
func TestApplyRead_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	ip := &IdentityProviderRead{
		Alias: "w", Protocol: "eudi-wallet", DisplayName: "Wallet", Enabled: true,
		Config: map[string]any{
			"accessKeyRef":               "software:gov/primary",
			"minimumLoa":                 "http://eidas.europa.eu/LoA/high",
			"statusList.required":        "true",
			"statusList.maxCacheSeconds": "900",
			"pid.requestedClaims":        `["given_name","family_name","birthdate"]`,
		},
	}
	var m1, m2 walletIdentityProviderModel
	applyRead(ctx, &m1, ip)
	applyRead(ctx, &m2, ip)
	if m1.MinimumLoa != m2.MinimumLoa || m1.StatusListRequired != m2.StatusListRequired ||
		m1.StatusListMaxCacheSeconds != m2.StatusListMaxCacheSeconds {
		t.Fatalf("applyRead must be deterministic: m1=%+v m2=%+v", m1, m2)
	}
	if !m1.StatusListRequired.ValueBool() {
		t.Fatalf("expected statusList.required=true to decode as true")
	}
	if m1.StatusListMaxCacheSeconds.ValueInt64() != 900 {
		t.Fatalf("expected statusList.maxCacheSeconds=900, got %d", m1.StatusListMaxCacheSeconds.ValueInt64())
	}
}

// --- import -----------------------------------------------------------------------------------------------

func TestImportState_SetsAliasAndID(t *testing.T) {
	ctx := context.Background()
	r := &walletIdentityProviderResource{}
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	sch := schemaResp.Schema

	objType := sch.Type().TerraformType(ctx).(tftypes.Object)
	vals := map[string]tftypes.Value{}
	for name, at := range objType.AttributeTypes {
		vals[name] = tftypes.NewValue(at, nil)
	}
	raw := tftypes.NewValue(objType, vals)

	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: sch, Raw: raw}}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "eudi-wallet"}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("import diagnostics: %v", resp.Diagnostics)
	}

	var m walletIdentityProviderModel
	if diags := resp.State.Get(ctx, &m); diags.HasError() {
		t.Fatalf("reading imported state: %v", diags)
	}
	if m.Alias.ValueString() != "eudi-wallet" {
		t.Fatalf("expected alias to be set from the import id, got %q", m.Alias.ValueString())
	}
	if m.ID.ValueString() != "eudi-wallet" {
		t.Fatalf("expected id to be set from the import id, got %q", m.ID.ValueString())
	}
}
