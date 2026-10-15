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
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
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
	w, diags := m.toWrite(ctx)
	if diags.HasError() {
		t.Fatalf("toWrite: %v", diags)
	}
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
	w, wdiags := m.toWrite(ctx)
	if wdiags.HasError() {
		t.Fatalf("toWrite: %v", wdiags)
	}
	if w.Config["credentialFormats"] != `["dc+sd-jwt","mso_mdoc"]` {
		t.Fatalf("unexpected JSON encoding: %q", w.Config["credentialFormats"])
	}
}

// TestToWrite_UnknownListIsADiagnostic: putList must not silently drop a list whose value cannot be
// determined yet — it should never actually reach here in practice (these are plain Optional, not
// Computed, attributes), but if it ever does, dropping it silently would write an incomplete config.
func TestToWrite_UnknownListIsADiagnostic(t *testing.T) {
	ctx := context.Background()
	m := walletIdentityProviderModel{Alias: types.StringValue("w"), CredentialFormats: types.ListUnknown(types.StringType)}
	_, diags := m.toWrite(ctx)
	if !diags.HasError() {
		t.Fatalf("expected a diagnostic for an unknown credential_formats value")
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
	if m.DcqlTrustedAuthorities.IsNull() == false {
		t.Fatalf("dcql_trusted_authorities absent server-side (server default applies) must read back as null, got %v", m.DcqlTrustedAuthorities)
	}
	var formats []string
	if diags := m.CredentialFormats.ElementsAs(ctx, &formats, false); diags.HasError() || len(formats) != 1 || formats[0] != "dc+sd-jwt" {
		t.Fatalf("unexpected credential_formats: %v (diags %v)", formats, diags)
	}
}

// --- dcql_trusted_authorities (master 201cb40e: WalletProviderConfig's "dcql.trustedAuthorities", a
// nullable boolean read via Reader.optionalBool — unset is a real, distinct state from false, since the
// server default (on for x509_hash + direct_post.jwt, off otherwise) only applies when the key is absent
// entirely) ---------------------------------------------------------------------------------------------

func TestToWrite_DcqlTrustedAuthorities_OmittedWhenUnset(t *testing.T) {
	ctx := context.Background()
	m := walletIdentityProviderModel{Alias: types.StringValue("w"), DcqlTrustedAuthorities: types.BoolNull()}
	w, diags := m.toWrite(ctx)
	if diags.HasError() {
		t.Fatalf("toWrite: %v", diags)
	}
	if _, ok := w.Config["dcql.trustedAuthorities"]; ok {
		t.Fatalf("unset dcql_trusted_authorities must be omitted so the server default applies, got %q",
			w.Config["dcql.trustedAuthorities"])
	}
}

func TestToWrite_DcqlTrustedAuthorities_EncodesExplicitValue(t *testing.T) {
	ctx := context.Background()
	for _, want := range []bool{true, false} {
		m := walletIdentityProviderModel{Alias: types.StringValue("w"), DcqlTrustedAuthorities: types.BoolValue(want)}
		w, diags := m.toWrite(ctx)
		if diags.HasError() {
			t.Fatalf("toWrite: %v", diags)
		}
		if got := w.Config["dcql.trustedAuthorities"]; got != strconv.FormatBool(want) {
			t.Fatalf("expected dcql.trustedAuthorities=%v, got %q", want, got)
		}
	}
}

func TestApplyRead_DcqlTrustedAuthorities_RoundTrips(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		ip   *IdentityProviderRead
		want types.Bool
	}{
		{"absent", &IdentityProviderRead{Config: map[string]any{}}, types.BoolNull()},
		{"true", &IdentityProviderRead{Config: map[string]any{"dcql.trustedAuthorities": "true"}}, types.BoolValue(true)},
		{"false", &IdentityProviderRead{Config: map[string]any{"dcql.trustedAuthorities": "false"}}, types.BoolValue(false)},
	} {
		var m walletIdentityProviderModel
		applyRead(ctx, &m, tc.ip)
		if !m.DcqlTrustedAuthorities.Equal(tc.want) {
			t.Fatalf("%s: expected %v, got %v", tc.name, tc.want, m.DcqlTrustedAuthorities)
		}
	}
}

// TestResource_DcqlTrustedAuthorities_NoDrift: leaving the attribute unset through a full
// create+read+no-op-update cycle must never introduce a diff — the server never stores a default for it
// (it is computed at use time, not at save time, same as every other defaulted field), so an omitted
// write must read back exactly as unset, every time.
func TestResource_DcqlTrustedAuthorities_NoDrift(t *testing.T) {
	srv, _ := newFakeIdentityProviderServer(t)
	defer srv.Close()
	c := newWalletClient(srv.URL)
	ctx := context.Background()
	r := &walletIdentityProviderResource{client: c}
	sch := walletSchema(ctx, t)

	createResp := &resource.CreateResponse{State: newState(ctx, t, sch, &walletIdentityProviderModel{})}
	r.Create(ctx, resource.CreateRequest{Plan: newPlan(ctx, t, sch, &walletIdentityProviderModel{
		Alias:        types.StringValue("trusted-authorities-wallet"),
		AccessKeyRef: types.StringValue("software:gov/primary"),
		// dcql_trusted_authorities left unset.
	})}, createResp)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("create: %v", createResp.Diagnostics)
	}
	var afterCreate walletIdentityProviderModel
	createResp.State.Get(ctx, &afterCreate)
	if !afterCreate.DcqlTrustedAuthorities.IsNull() {
		t.Fatalf("expected dcql_trusted_authorities to stay null after create, got %v", afterCreate.DcqlTrustedAuthorities)
	}

	noOpResp := &resource.UpdateResponse{State: createResp.State}
	r.Update(ctx, resource.UpdateRequest{
		State: createResp.State,
		Plan:  newPlan(ctx, t, sch, &afterCreate), // the plan is exactly what Create just produced
	}, noOpResp)
	if noOpResp.Diagnostics.HasError() {
		t.Fatalf("no-op update: %v", noOpResp.Diagnostics)
	}
	var afterNoOp walletIdentityProviderModel
	noOpResp.State.Get(ctx, &afterNoOp)
	if !afterNoOp.DcqlTrustedAuthorities.Equal(afterCreate.DcqlTrustedAuthorities) {
		t.Fatalf("a no-op plan must not drift dcql_trusted_authorities: before=%v after=%v",
			afterCreate.DcqlTrustedAuthorities, afterNoOp.DcqlTrustedAuthorities)
	}

	// Setting it explicitly must round-trip too, and stay stable on a second no-op update.
	explicitResp := &resource.UpdateResponse{State: noOpResp.State}
	r.Update(ctx, resource.UpdateRequest{
		State: noOpResp.State,
		Plan: newPlan(ctx, t, sch, &walletIdentityProviderModel{
			Alias:                  types.StringValue("trusted-authorities-wallet"),
			AccessKeyRef:           types.StringValue("software:gov/primary"),
			DcqlTrustedAuthorities: types.BoolValue(true),
		}),
	}, explicitResp)
	if explicitResp.Diagnostics.HasError() {
		t.Fatalf("update (set true): %v", explicitResp.Diagnostics)
	}
	var afterExplicit walletIdentityProviderModel
	explicitResp.State.Get(ctx, &afterExplicit)
	if !afterExplicit.DcqlTrustedAuthorities.Equal(types.BoolValue(true)) {
		t.Fatalf("expected dcql_trusted_authorities=true after setting it, got %v", afterExplicit.DcqlTrustedAuthorities)
	}

	stableResp := &resource.UpdateResponse{State: explicitResp.State}
	r.Update(ctx, resource.UpdateRequest{
		State: explicitResp.State,
		Plan:  newPlan(ctx, t, sch, &afterExplicit),
	}, stableResp)
	if stableResp.Diagnostics.HasError() {
		t.Fatalf("no-op update (explicit true): %v", stableResp.Diagnostics)
	}
	var afterStable walletIdentityProviderModel
	stableResp.State.Get(ctx, &afterStable)
	if !afterStable.DcqlTrustedAuthorities.Equal(types.BoolValue(true)) {
		t.Fatalf("expected dcql_trusted_authorities to stay true, got %v", afterStable.DcqlTrustedAuthorities)
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

// TestApplyRead_IsIdempotent: a SECOND refresh of a resource that was actually created against a server
// (not two fresh, never-applied models — comparing those proves nothing, since neither carries any
// history) must land on exactly the same values as the first. m2 starts as a copy of m1 (the real state
// left behind by the first read), the way Terraform's Read always starts from the current state, not a
// blank model; only then is a second, independent GET overlaid onto it.
func TestApplyRead_IsIdempotent(t *testing.T) {
	srv, _ := newFakeIdentityProviderServer(t)
	defer srv.Close()
	c := newWalletClient(srv.URL)
	ctx := context.Background()

	if err := c.CreateIdentityProvider(ctx, IdentityProviderWrite{
		Alias: "idempotent-wallet", Protocol: "eudi-wallet", DisplayName: "Wallet", Enabled: true,
		Config: map[string]string{
			"accessKeyRef":               "software:gov/primary",
			"minimumLoa":                 "http://eidas.europa.eu/LoA/high",
			"statusList.required":        "true",
			"statusList.maxCacheSeconds": "900",
			"pid.requestedClaims":        `["given_name","family_name","birthdate"]`,
		},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	m1 := walletIdentityProviderModel{Alias: types.StringValue("idempotent-wallet")}
	ip1, _, err := c.GetIdentityProvider(ctx, "idempotent-wallet")
	if err != nil {
		t.Fatalf("get 1: %v", err)
	}
	applyRead(ctx, &m1, ip1)

	m2 := m1 // start from the real state the first read produced, not a blank model
	ip2, _, err := c.GetIdentityProvider(ctx, "idempotent-wallet")
	if err != nil {
		t.Fatalf("get 2: %v", err)
	}
	applyRead(ctx, &m2, ip2)

	if m1.MinimumLoa != m2.MinimumLoa || m1.StatusListRequired != m2.StatusListRequired ||
		m1.StatusListMaxCacheSeconds != m2.StatusListMaxCacheSeconds {
		t.Fatalf("a second refresh must be deterministic: m1=%+v m2=%+v", m1, m2)
	}
	if !m1.PidRequestedClaims.Equal(m2.PidRequestedClaims) {
		t.Fatalf("a second refresh must not drift pid_requested_claims: m1=%v m2=%v", m1.PidRequestedClaims, m2.PidRequestedClaims)
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

// TestNotEmptyStringValidator rejects "" but passes null (unset) and unknown (not yet computable) values.
func TestNotEmptyStringValidator(t *testing.T) {
	ctx := context.Background()
	v := notEmptyStringValidator{}
	for name, value := range map[string]types.String{
		"null":    types.StringNull(),
		"unknown": types.StringUnknown(),
		"set":     types.StringValue("Acme Wallet"),
	} {
		resp := &validator.StringResponse{}
		v.ValidateString(ctx, validator.StringRequest{Path: path.Root("display_name"), ConfigValue: value}, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("%s: expected no error, got %v", name, resp.Diagnostics)
		}
	}

	resp := &validator.StringResponse{}
	v.ValidateString(ctx, validator.StringRequest{Path: path.Root("display_name"), ConfigValue: types.StringValue("")}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatalf("expected an empty string to be rejected")
	}
}

// --- resource-level tests: Create/Read/Update/Delete/Import through the real framework types ------------
//
// These drive walletIdentityProviderResource's own Create/Read/Update/ImportState methods with real
// tfsdk.Plan/tfsdk.State values built against the resource's own schema (not just the model <-> wire
// helpers in isolation), against the same fake admin API used above.

func walletSchema(ctx context.Context, t *testing.T) schema.Schema {
	t.Helper()
	r := &walletIdentityProviderResource{}
	resp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("building schema: %v", resp.Diagnostics)
	}
	return resp.Schema
}

// nullObject is every attribute of sch set to null — a valid, empty starting point for Set to overwrite.
func nullObject(ctx context.Context, sch schema.Schema) tftypes.Value {
	objType := sch.Type().TerraformType(ctx).(tftypes.Object)
	vals := map[string]tftypes.Value{}
	for name, at := range objType.AttributeTypes {
		vals[name] = tftypes.NewValue(at, nil)
	}
	return tftypes.NewValue(objType, vals)
}

// normalizeListDefaults replaces any list attribute left at its Go zero value (types.List{}, which has no
// ElementType and so cannot be converted against the schema's typed list attributes) with a properly
// typed null list — i.e. "not set", exactly like an omitted HCL attribute. Test literals only set the
// list fields they care about; this lets them leave the rest out instead of spelling out
// types.ListNull(types.StringType) for every one, every time.
func normalizeListDefaults(ctx context.Context, m *walletIdentityProviderModel) {
	for _, l := range []*types.List{
		&m.CredentialFormats, &m.PidSdJwtVcts, &m.PidRequestedClaims,
		&m.CustomCredentialQueries, &m.StatusListAllowedHosts,
	} {
		if l.ElementType(ctx) == nil {
			*l = types.ListNull(types.StringType)
		}
	}
}

func newPlan(ctx context.Context, t *testing.T, sch schema.Schema, m *walletIdentityProviderModel) tfsdk.Plan {
	t.Helper()
	normalizeListDefaults(ctx, m)
	p := tfsdk.Plan{Schema: sch, Raw: nullObject(ctx, sch)}
	if diags := p.Set(ctx, m); diags.HasError() {
		t.Fatalf("building plan: %v", diags)
	}
	return p
}

func newState(ctx context.Context, t *testing.T, sch schema.Schema, m *walletIdentityProviderModel) tfsdk.State {
	t.Helper()
	normalizeListDefaults(ctx, m)
	s := tfsdk.State{Schema: sch, Raw: nullObject(ctx, sch)}
	if diags := s.Set(ctx, m); diags.HasError() {
		t.Fatalf("building state: %v", diags)
	}
	return s
}

// attributeErrors returns the attribute path of every error-severity diagnostic that carries one.
func attributeErrors(diags diag.Diagnostics) []path.Path {
	var paths []path.Path
	for _, d := range diags.Errors() {
		if wp, ok := d.(diag.DiagnosticWithPath); ok {
			paths = append(paths, wp.Path())
		}
	}
	return paths
}

func containsPath(paths []path.Path, want path.Path) bool {
	for _, p := range paths {
		if p.Equal(want) {
			return true
		}
	}
	return false
}

func TestResource_CreateReadUpdate(t *testing.T) {
	srv, _ := newFakeIdentityProviderServer(t)
	defer srv.Close()
	c := newWalletClient(srv.URL)
	ctx := context.Background()
	r := &walletIdentityProviderResource{client: c}
	sch := walletSchema(ctx, t)

	createResp := &resource.CreateResponse{State: newState(ctx, t, sch, &walletIdentityProviderModel{})}
	r.Create(ctx, resource.CreateRequest{Plan: newPlan(ctx, t, sch, &walletIdentityProviderModel{
		Alias:        types.StringValue("w1"),
		DisplayName:  types.StringValue("Wallet One"),
		AccessKeyRef: types.StringValue("software:gov/primary"),
		MinimumLoa:   types.StringValue("http://eidas.europa.eu/LoA/high"),
	})}, createResp)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("create: %v", createResp.Diagnostics)
	}
	var afterCreate walletIdentityProviderModel
	if diags := createResp.State.Get(ctx, &afterCreate); diags.HasError() {
		t.Fatalf("reading created state: %v", diags)
	}
	if afterCreate.ID.ValueString() != "w1" || afterCreate.AccessKeyRef.ValueString() != "software:gov/primary" {
		t.Fatalf("unexpected state after create: %+v", afterCreate)
	}
	if afterCreate.ClientIDHost.IsNull() == false {
		t.Fatalf("an attribute never set must read back null, got %v", afterCreate.ClientIDHost)
	}

	readResp := &resource.ReadResponse{State: createResp.State}
	r.Read(ctx, resource.ReadRequest{State: createResp.State}, readResp)
	if readResp.Diagnostics.HasError() {
		t.Fatalf("read: %v", readResp.Diagnostics)
	}
	var afterRead walletIdentityProviderModel
	if diags := readResp.State.Get(ctx, &afterRead); diags.HasError() {
		t.Fatalf("reading read state: %v", diags)
	}
	if afterRead.DisplayName.ValueString() != "Wallet One" {
		t.Fatalf("expected displayName to round-trip, got %q", afterRead.DisplayName.ValueString())
	}

	updateResp := &resource.UpdateResponse{State: readResp.State}
	r.Update(ctx, resource.UpdateRequest{
		State: readResp.State,
		Plan: newPlan(ctx, t, sch, &walletIdentityProviderModel{
			Alias:        types.StringValue("w1"),
			DisplayName:  types.StringValue("Wallet One Updated"),
			AccessKeyRef: types.StringValue("software:gov/secondary"),
			MinimumLoa:   types.StringValue("http://eidas.europa.eu/LoA/high"),
		}),
	}, updateResp)
	if updateResp.Diagnostics.HasError() {
		t.Fatalf("update: %v", updateResp.Diagnostics)
	}
	var afterUpdate walletIdentityProviderModel
	if diags := updateResp.State.Get(ctx, &afterUpdate); diags.HasError() {
		t.Fatalf("reading updated state: %v", diags)
	}
	if afterUpdate.DisplayName.ValueString() != "Wallet One Updated" || afterUpdate.AccessKeyRef.ValueString() != "software:gov/secondary" {
		t.Fatalf("unexpected state after update: %+v", afterUpdate)
	}
}

// TestResource_UpdateSecret covers both halves of the ruling: an update that simply omits the secret
// keeps it stored server-side (the attribute stays whatever it already was in state — unmanaged, not
// cleared); an update that goes from a set value to explicitly null sends the clear flag and the server
// actually removes it.
func TestResource_UpdateSecret(t *testing.T) {
	srv, fake := newFakeIdentityProviderServer(t)
	defer srv.Close()
	c := newWalletClient(srv.URL)
	ctx := context.Background()
	r := &walletIdentityProviderResource{client: c}
	sch := walletSchema(ctx, t)

	createResp := &resource.CreateResponse{State: newState(ctx, t, sch, &walletIdentityProviderModel{})}
	r.Create(ctx, resource.CreateRequest{Plan: newPlan(ctx, t, sch, &walletIdentityProviderModel{
		Alias:                       types.StringValue("dev-wallet"),
		AccessCertificatePrivateKey: types.StringValue("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"),
	})}, createResp)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("create: %v", createResp.Diagnostics)
	}
	var afterCreate walletIdentityProviderModel
	createResp.State.Get(ctx, &afterCreate)
	if afterCreate.AccessCertificatePrivateKey.ValueString() == "" {
		t.Fatalf("expected the secret to be carried into state right after create")
	}

	// 1) Update something else, plan still carries the secret (unchanged) — no clear flag, server keeps it.
	unchangedResp := &resource.UpdateResponse{State: createResp.State}
	r.Update(ctx, resource.UpdateRequest{
		State: createResp.State,
		Plan: newPlan(ctx, t, sch, &walletIdentityProviderModel{
			Alias:                       types.StringValue("dev-wallet"),
			ClientIDHost:                types.StringValue("verifier.example"),
			AccessCertificatePrivateKey: afterCreate.AccessCertificatePrivateKey,
		}),
	}, unchangedResp)
	if unchangedResp.Diagnostics.HasError() {
		t.Fatalf("update (unrelated field): %v", unchangedResp.Diagnostics)
	}
	if set, _ := fake.stored["dev-wallet"][walletSecretKey]; set == "" {
		t.Fatalf("the secret must still be stored after an unrelated update")
	}

	// 2) Update again, this time the plan drops the secret (removed from config) — must send the clear
	// flag and the server must actually remove it, not just leave Terraform's state null while the old
	// value lingers server-side.
	clearedResp := &resource.UpdateResponse{State: unchangedResp.State}
	r.Update(ctx, resource.UpdateRequest{
		State: unchangedResp.State,
		Plan: newPlan(ctx, t, sch, &walletIdentityProviderModel{
			Alias:        types.StringValue("dev-wallet"),
			ClientIDHost: types.StringValue("verifier.example"),
			// AccessCertificatePrivateKey left null: removed from the configuration.
		}),
	}, clearedResp)
	if clearedResp.Diagnostics.HasError() {
		t.Fatalf("update (clearing secret): %v", clearedResp.Diagnostics)
	}
	if _, present := fake.stored["dev-wallet"][walletSecretKey]; present {
		t.Fatalf("expected the secret to be actually removed server-side after a declarative removal")
	}
	var afterClear walletIdentityProviderModel
	clearedResp.State.Get(ctx, &afterClear)
	if !afterClear.AccessCertificatePrivateKey.IsNull() {
		t.Fatalf("expected the secret attribute to read back null after clearing, got %q", afterClear.AccessCertificatePrivateKey.ValueString())
	}
}

// TestResource_ImportNeverSendsClearFlag: right after import, state has no value for the secret (it was
// never read from the server — it can't be). An update must not treat that null as "please clear it".
func TestResource_ImportNeverSendsClearFlag(t *testing.T) {
	srv, fake := newFakeIdentityProviderServer(t)
	defer srv.Close()
	c := newWalletClient(srv.URL)
	ctx := context.Background()
	r := &walletIdentityProviderResource{client: c}
	sch := walletSchema(ctx, t)

	if err := c.CreateIdentityProvider(ctx, IdentityProviderWrite{
		Alias: "imported-dev-wallet", Protocol: "eudi-wallet", Enabled: true,
		Config: map[string]string{walletSecretKey: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	importResp := &resource.ImportStateResponse{State: tfsdk.State{Schema: sch, Raw: nullObject(ctx, sch)}}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "imported-dev-wallet"}, importResp)
	if importResp.Diagnostics.HasError() {
		t.Fatalf("import: %v", importResp.Diagnostics)
	}
	readResp := &resource.ReadResponse{State: importResp.State}
	r.Read(ctx, resource.ReadRequest{State: importResp.State}, readResp)
	if readResp.Diagnostics.HasError() {
		t.Fatalf("read after import: %v", readResp.Diagnostics)
	}
	var afterImportRead walletIdentityProviderModel
	readResp.State.Get(ctx, &afterImportRead)
	if !afterImportRead.AccessCertificatePrivateKey.IsNull() {
		t.Fatalf("expected the secret to stay null right after import, got %q", afterImportRead.AccessCertificatePrivateKey.ValueString())
	}

	// A no-op update (nothing in the plan changed from the imported state) must not clear the secret.
	updateResp := &resource.UpdateResponse{State: readResp.State}
	r.Update(ctx, resource.UpdateRequest{
		State: readResp.State,
		Plan:  newPlan(ctx, t, sch, &afterImportRead),
	}, updateResp)
	if updateResp.Diagnostics.HasError() {
		t.Fatalf("no-op update after import: %v", updateResp.Diagnostics)
	}
	if secret, present := fake.stored["imported-dev-wallet"][walletSecretKey]; !present || secret == "" {
		t.Fatalf("expected the secret to remain stored after an update that followed an import, got present=%v value=%q", present, secret)
	}
}

// TestResource_FieldErrorsBecomeAttributeDiagnostics: a 400 with fieldErrors must become one Terraform
// diagnostic per field, mapped to the right attribute where this resource knows the mapping.
func TestResource_FieldErrorsBecomeAttributeDiagnostics(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/realms/master/identity-providers", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "Wallet provider 'w' is invalid",
			"fieldErrors": map[string]string{
				"alias":               "alias is required",
				"config.accessKeyRef": "accessKeyRef is required (a signing key imported into this realm)",
				"config.minimumLoa":   "minimumLoa must be an eIDAS level of assurance",
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := newWalletClient(srv.URL)
	ctx := context.Background()
	r := &walletIdentityProviderResource{client: c}
	sch := walletSchema(ctx, t)

	createResp := &resource.CreateResponse{State: newState(ctx, t, sch, &walletIdentityProviderModel{})}
	r.Create(ctx, resource.CreateRequest{Plan: newPlan(ctx, t, sch, &walletIdentityProviderModel{
		Alias: types.StringValue("w"),
	})}, createResp)

	if !createResp.Diagnostics.HasError() {
		t.Fatalf("expected diagnostics from the 400 response")
	}
	if got := createResp.Diagnostics.ErrorsCount(); got != 3 {
		t.Fatalf("expected 3 field errors to become 3 diagnostics, got %d: %v", got, createResp.Diagnostics)
	}
	paths := attributeErrors(createResp.Diagnostics)
	for _, want := range []path.Path{path.Root("alias"), path.Root("access_key_ref"), path.Root("minimum_loa")} {
		if !containsPath(paths, want) {
			t.Fatalf("expected an attribute error on %v, got paths %v (diagnostics: %v)", want, paths, createResp.Diagnostics)
		}
	}
}

// TestResource_ImportReadThenNoOpUpdate_HasNoDrift: import an existing connection, refresh it, then run
// an "update" whose plan is exactly the state Read just produced (what Terraform does when the
// configuration already matches reality) — nothing may change, server-side or in the resulting state.
func TestResource_ImportReadThenNoOpUpdate_HasNoDrift(t *testing.T) {
	srv, _ := newFakeIdentityProviderServer(t)
	defer srv.Close()
	c := newWalletClient(srv.URL)
	ctx := context.Background()
	r := &walletIdentityProviderResource{client: c}
	sch := walletSchema(ctx, t)

	if err := c.CreateIdentityProvider(ctx, IdentityProviderWrite{
		Alias: "imported-wallet", Protocol: "eudi-wallet", DisplayName: "Imported", Enabled: true,
		Config: map[string]string{
			"accessKeyRef": "software:gov/primary",
			"minimumLoa":   "http://eidas.europa.eu/LoA/high",
		},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	importResp := &resource.ImportStateResponse{State: tfsdk.State{Schema: sch, Raw: nullObject(ctx, sch)}}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "imported-wallet"}, importResp)
	if importResp.Diagnostics.HasError() {
		t.Fatalf("import: %v", importResp.Diagnostics)
	}
	readResp := &resource.ReadResponse{State: importResp.State}
	r.Read(ctx, resource.ReadRequest{State: importResp.State}, readResp)
	if readResp.Diagnostics.HasError() {
		t.Fatalf("read after import: %v", readResp.Diagnostics)
	}
	var afterImport walletIdentityProviderModel
	readResp.State.Get(ctx, &afterImport)
	if afterImport.AccessKeyRef.ValueString() != "software:gov/primary" {
		t.Fatalf("expected access_key_ref to come back from the import+read, got %q", afterImport.AccessKeyRef.ValueString())
	}

	noOpResp := &resource.UpdateResponse{State: readResp.State}
	r.Update(ctx, resource.UpdateRequest{
		State: readResp.State,
		Plan:  newPlan(ctx, t, sch, &afterImport), // the plan is exactly what Read just produced
	}, noOpResp)
	if noOpResp.Diagnostics.HasError() {
		t.Fatalf("no-op update: %v", noOpResp.Diagnostics)
	}
	var afterNoOp walletIdentityProviderModel
	noOpResp.State.Get(ctx, &afterNoOp)

	if afterImport.AccessKeyRef != afterNoOp.AccessKeyRef || afterImport.MinimumLoa != afterNoOp.MinimumLoa ||
		afterImport.DisplayName != afterNoOp.DisplayName || afterImport.Enabled != afterNoOp.Enabled {
		t.Fatalf("a no-op plan must not drift: before=%+v after=%+v", afterImport, afterNoOp)
	}
}
