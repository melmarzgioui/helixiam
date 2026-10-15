/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// walletProtocol is the canonical protocol value the admin API documents for an EUDI wallet connection
// (docs/eudi-wallet.md §2.4). "openid4vp" and "wallet" are accepted aliases server-side
// (FederationProviderFactory.isWallet) but the resource always writes the canonical one.
const walletProtocol = "eudi-wallet"

type walletIdentityProviderResource struct{ client *Client }

var (
	_ resource.Resource                = &walletIdentityProviderResource{}
	_ resource.ResourceWithImportState = &walletIdentityProviderResource{}
)

// walletIdentityProviderModel mirrors WalletProviderConfig's stored flat map (helix-iam-server
// WalletProviderConfig.java, allStored()/parseStored()) one attribute per stored key, snake_cased.
// Two fields are intentionally left out of this resource because they are not functional per-connection
// settings: "accessCertificateKeyRef" (the pre-rename spec field name; WalletConfigValidator always
// refuses it with "renamed to accessKeyRef") and "subjectPepper" (declared as a wallet secret key in
// ProviderSecretKeys for defensive masking, but the wallet subject HMAC pepper is realm-level, generated
// lazily server-side by RealmWalletPepper and never read from identity-provider config).
type walletIdentityProviderModel struct {
	Alias       types.String `tfsdk:"alias"`
	DisplayName types.String `tfsdk:"display_name"`
	Enabled     types.Bool   `tfsdk:"enabled"`

	ClientIDScheme                types.String `tfsdk:"client_id_scheme"`
	ClientIDHost                  types.String `tfsdk:"client_id_host"`
	AccessKeyRef                  types.String `tfsdk:"access_key_ref"`
	AccessCertificateChain        types.String `tfsdk:"access_certificate_chain"`
	AccessCertificatePrivateKey   types.String `tfsdk:"access_certificate_private_key"`
	RegistrationCertificate       types.String `tfsdk:"registration_certificate"`
	InvocationScheme              types.String `tfsdk:"invocation_scheme"`
	ResponseMode                  types.String `tfsdk:"response_mode"`
	RequestURIMethod              types.String `tfsdk:"request_uri_method"`
	TransactionTTLSeconds         types.Int64  `tfsdk:"transaction_ttl_seconds"`
	CredentialFormats             types.List   `tfsdk:"credential_formats"`
	PidSdJwtVcts                  types.List   `tfsdk:"pid_sd_jwt_vcts"`
	PidMdocDoctype                types.String `tfsdk:"pid_mdoc_doctype"`
	PidRequestedClaims            types.List   `tfsdk:"pid_requested_claims"`
	CustomCredentialQueries       types.List   `tfsdk:"custom_credential_queries"`
	TrustAnchors                  types.String `tfsdk:"trust_anchors"`
	RevocationChecking            types.String `tfsdk:"revocation_checking"`
	StatusListRequired            types.Bool   `tfsdk:"status_list_required"`
	StatusListOnUnavailable       types.String `tfsdk:"status_list_on_unavailable"`
	StatusListMaxCacheSeconds     types.Int64  `tfsdk:"status_list_max_cache_seconds"`
	StatusListAllowedHosts        types.List   `tfsdk:"status_list_allowed_hosts"`
	SubjectStrategy               types.String `tfsdk:"subject_strategy"`
	SubjectAcknowledgeWeakSubject types.Bool   `tfsdk:"subject_acknowledge_weak_subject"`
	MinimumLoa                    types.String `tfsdk:"minimum_loa"`
	ClockSkewSeconds              types.Int64  `tfsdk:"clock_skew_seconds"`
	AllowLegacyVcSdJwtTyp         types.Bool   `tfsdk:"allow_legacy_vc_sd_jwt_typ"`
	LimitsMaxJwtBytes             types.Int64  `tfsdk:"limits_max_jwt_bytes"`
	LimitsCborMaxDepth            types.Int64  `tfsdk:"limits_cbor_max_depth"`
	LimitsCborMaxItems            types.Int64  `tfsdk:"limits_cbor_max_items"`
	LimitsCborMaxBytes            types.Int64  `tfsdk:"limits_cbor_max_bytes"`

	ID types.String `tfsdk:"id"`
}

func NewWalletIdentityProviderResource() resource.Resource { return &walletIdentityProviderResource{} }

func (r *walletIdentityProviderResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_wallet_identity_provider"
}

func (r *walletIdentityProviderResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An EUDI Wallet (OpenID4VP verifier) identity-provider connection — a realm's " +
			"`identity-providers` admin resource with protocol `eudi-wallet` (see `docs/eudi-wallet.md`). Every " +
			"attribute below is a key of that connection's flat `config` map (nested settings dotted, e.g. " +
			"`pid.requestedClaims`); an attribute left unset is left out of the write, so the server's own default " +
			"applies and a `terraform plan` never shows drift for it. `access_certificate_private_key` (the dev-only " +
			"raw signing key) is write-only: the admin API never returns secret values, only whether one is set, so " +
			"Terraform cannot read it back — it keeps whatever is in state. To actually remove it, recreate the " +
			"resource or clear it through the admin API directly.",
		Attributes: map[string]schema.Attribute{
			"alias": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Unique alias for this connection within the realm (the natural key).",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"display_name": schema.StringAttribute{Optional: true, MarkdownDescription: "Label shown in the console and on the login page."},
			"enabled":      schema.BoolAttribute{Optional: true, Computed: true, MarkdownDescription: "Whether the connection is offered at login (default true)."},

			"client_id_scheme":                 schema.StringAttribute{Optional: true, MarkdownDescription: "`client_id` prefix scheme (OpenID4VP §5.9.3): `x509_hash` (default) or `x509_san_dns`."},
			"client_id_host":                   schema.StringAttribute{Optional: true, MarkdownDescription: "DNS host asserted as `client_id`; required, and must be a SAN of the access certificate, when `client_id_scheme = \"x509_san_dns\"`."},
			"access_key_ref":                   schema.StringAttribute{Optional: true, MarkdownDescription: "Reference to the realm signing key used as the verifier's access key (e.g. `software:gov/primary`, imported via `/admin/realms/{realm}/verifier-keys`). Required unless the dev-only `access_certificate_private_key` is used instead."},
			"access_certificate_chain":         schema.StringAttribute{Optional: true, MarkdownDescription: "PEM certificate chain (leaf first, no root) for the access key. With `access_key_ref` it must equal that key's own chain; it is the source of the request object's `x5c` only with `access_certificate_private_key`."},
			"access_certificate_private_key":   schema.StringAttribute{Optional: true, Sensitive: true, MarkdownDescription: "Dev-profile-only raw PEM private key, as an alternative to `access_key_ref`. Never returned by the admin API; see the resource description."},
			"registration_certificate":         schema.StringAttribute{Optional: true, MarkdownDescription: "PEM certificate bundle for OpenID Federation registration, if used."},
			"invocation_scheme":                schema.StringAttribute{Optional: true, MarkdownDescription: "URI scheme used to invoke the wallet (default `haip-vp`, e.g. `openid4vp`, `eudi-openid4vp`)."},
			"response_mode":                    schema.StringAttribute{Optional: true, MarkdownDescription: "OpenID4VP response mode: `direct_post.jwt` (default, encrypted) or `direct_post` (unencrypted, dev profile only)."},
			"request_uri_method":               schema.StringAttribute{Optional: true, MarkdownDescription: "`request_uri_method`: `get` (default) or `post`."},
			"transaction_ttl_seconds":          schema.Int64Attribute{Optional: true, MarkdownDescription: "How long a started transaction (and its QR code) stays valid, 60–900 seconds (default 300)."},
			"credential_formats":               schema.ListAttribute{Optional: true, ElementType: types.StringType, MarkdownDescription: "Accepted credential formats: `dc+sd-jwt` and/or `mso_mdoc` (default both)."},
			"pid_sd_jwt_vcts":                  schema.ListAttribute{Optional: true, ElementType: types.StringType, MarkdownDescription: "Accepted SD-JWT VC `vct` values for the PID (default `[\"urn:eudi:pid:1\", \"urn:eudi:pid:de:1\"]`)."},
			"pid_mdoc_doctype":                 schema.StringAttribute{Optional: true, MarkdownDescription: "mdoc PID doctype (default the ISO/IEC 23220 PID doctype)."},
			"pid_requested_claims":             schema.ListAttribute{Optional: true, ElementType: types.StringType, MarkdownDescription: "Canonical PID claim names requested (default `[\"given_name\", \"family_name\", \"birthdate\"]`)."},
			"custom_credential_queries":        schema.ListAttribute{Optional: true, ElementType: types.StringType, MarkdownDescription: "Custom DCQL credential queries. Not supported yet — any non-empty list is refused by the server."},
			"trust_anchors":                    schema.StringAttribute{Optional: true, MarkdownDescription: "PEM bundle of trusted PID-issuer CA certificates. At least one acceptable anchor is required."},
			"revocation_checking":              schema.StringAttribute{Optional: true, MarkdownDescription: "Issuer-certificate revocation mode (default `HARD_FAIL`); see docs/eudi-wallet.md §7.2."},
			"status_list_required":             schema.BoolAttribute{Optional: true, MarkdownDescription: "Refuse a credential with no Token Status List `status` claim (default false)."},
			"status_list_on_unavailable":       schema.StringAttribute{Optional: true, MarkdownDescription: "Policy when the status list cannot be fetched (default `FAIL_CLOSED`)."},
			"status_list_max_cache_seconds":    schema.Int64Attribute{Optional: true, MarkdownDescription: "Status-list cache TTL, 0–900 seconds (default 900)."},
			"status_list_allowed_hosts":        schema.ListAttribute{Optional: true, ElementType: types.StringType, MarkdownDescription: "Allow-listed status-list host names (bare host, no scheme/port/path); empty means any https host."},
			"subject_strategy":                 schema.StringAttribute{Optional: true, MarkdownDescription: "How the Helix subject is derived: `ADMINISTRATIVE_NUMBER` (default) or `ATTRIBUTE_TUPLE`. `NONE` is not supported yet."},
			"subject_acknowledge_weak_subject": schema.BoolAttribute{Optional: true, MarkdownDescription: "Required (`true`) to use `subject_strategy = \"ATTRIBUTE_TUPLE\"`, acknowledging its weaker, re-linkable subject binding."},
			"minimum_loa":                      schema.StringAttribute{Optional: true, MarkdownDescription: "Minimum eIDAS level of assurance asserted (default `http://eidas.europa.eu/LoA/high`)."},
			"clock_skew_seconds":               schema.Int64Attribute{Optional: true, MarkdownDescription: "Allowed clock skew when verifying presentation timestamps, 0–60 seconds (default 60)."},
			"allow_legacy_vc_sd_jwt_typ":       schema.BoolAttribute{Optional: true, MarkdownDescription: "Accept the legacy `vc+sd-jwt` SD-JWT `typ` header alongside `dc+sd-jwt` (default false)."},
			"limits_max_jwt_bytes":             schema.Int64Attribute{Optional: true, MarkdownDescription: "Maximum size in bytes of the response JWE and each JWT/SD-JWT within it (default 65536)."},
			"limits_cbor_max_depth":            schema.Int64Attribute{Optional: true, MarkdownDescription: "Maximum CBOR nesting depth parsed in an mdoc presentation."},
			"limits_cbor_max_items":            schema.Int64Attribute{Optional: true, MarkdownDescription: "Maximum CBOR map/array items parsed in an mdoc presentation."},
			"limits_cbor_max_bytes":            schema.Int64Attribute{Optional: true, MarkdownDescription: "Maximum CBOR byte-string length parsed in an mdoc presentation."},

			"id": schema.StringAttribute{Computed: true, MarkdownDescription: "The connection alias (resource id)."},
		},
	}
}

func (r *walletIdentityProviderResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *Client, got %T", req.ProviderData))
		return
	}
	r.client = c
}

// ImportState imports by alias: both "id" and "alias" are set from the import id so the following Read
// (which looks the connection up by m.Alias) finds it. Neither existing resource in this provider
// supports import; this one does, per the admin API's alias-keyed model.
func (r *walletIdentityProviderResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("alias"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// --- model <-> wire -------------------------------------------------------------------------------------

func putStr(cfg map[string]string, key string, v types.String) {
	if !v.IsNull() && !v.IsUnknown() {
		cfg[key] = v.ValueString()
	}
}

func putInt(cfg map[string]string, key string, v types.Int64) {
	if !v.IsNull() && !v.IsUnknown() {
		cfg[key] = strconv.FormatInt(v.ValueInt64(), 10)
	}
}

func putBool(cfg map[string]string, key string, v types.Bool) {
	if !v.IsNull() && !v.IsUnknown() {
		cfg[key] = strconv.FormatBool(v.ValueBool())
	}
}

func putList(ctx context.Context, cfg map[string]string, key string, v types.List) {
	if v.IsNull() || v.IsUnknown() {
		return
	}
	var elems []string
	if v.ElementsAs(ctx, &elems, false).HasError() {
		return
	}
	b, err := json.Marshal(elems)
	if err != nil {
		return
	}
	cfg[key] = string(b)
}

// toWrite builds the admin API request body. Any attribute left null/unknown in the model is left out of
// config, so the server's own default (never stored) applies and a later Read sees the same absence.
func (m *walletIdentityProviderModel) toWrite(ctx context.Context) IdentityProviderWrite {
	enabled := true
	if !m.Enabled.IsNull() && !m.Enabled.IsUnknown() {
		enabled = m.Enabled.ValueBool()
	}
	cfg := map[string]string{}
	putStr(cfg, "clientIdScheme", m.ClientIDScheme)
	putStr(cfg, "clientIdHost", m.ClientIDHost)
	putStr(cfg, "accessKeyRef", m.AccessKeyRef)
	putStr(cfg, "accessCertificateChain", m.AccessCertificateChain)
	putStr(cfg, "accessCertificatePrivateKey", m.AccessCertificatePrivateKey)
	putStr(cfg, "registrationCertificate", m.RegistrationCertificate)
	putStr(cfg, "invocationScheme", m.InvocationScheme)
	putStr(cfg, "responseMode", m.ResponseMode)
	putStr(cfg, "requestUriMethod", m.RequestURIMethod)
	putInt(cfg, "transactionTtlSeconds", m.TransactionTTLSeconds)
	putList(ctx, cfg, "credentialFormats", m.CredentialFormats)
	putList(ctx, cfg, "pid.sdJwtVcts", m.PidSdJwtVcts)
	putStr(cfg, "pid.mdocDoctype", m.PidMdocDoctype)
	putList(ctx, cfg, "pid.requestedClaims", m.PidRequestedClaims)
	putList(ctx, cfg, "customCredentialQueries", m.CustomCredentialQueries)
	putStr(cfg, "trustAnchors", m.TrustAnchors)
	putStr(cfg, "revocationChecking", m.RevocationChecking)
	putBool(cfg, "statusList.required", m.StatusListRequired)
	putStr(cfg, "statusList.onUnavailable", m.StatusListOnUnavailable)
	putInt(cfg, "statusList.maxCacheSeconds", m.StatusListMaxCacheSeconds)
	putList(ctx, cfg, "statusList.allowedHosts", m.StatusListAllowedHosts)
	putStr(cfg, "subject.strategy", m.SubjectStrategy)
	putBool(cfg, "subject.acknowledgeWeakSubject", m.SubjectAcknowledgeWeakSubject)
	putStr(cfg, "minimumLoa", m.MinimumLoa)
	putInt(cfg, "clockSkewSeconds", m.ClockSkewSeconds)
	putBool(cfg, "allowLegacyVcSdJwtTyp", m.AllowLegacyVcSdJwtTyp)
	putInt(cfg, "limits.maxJwtBytes", m.LimitsMaxJwtBytes)
	putInt(cfg, "limits.cborMaxDepth", m.LimitsCborMaxDepth)
	putInt(cfg, "limits.cborMaxItems", m.LimitsCborMaxItems)
	putInt(cfg, "limits.cborMaxBytes", m.LimitsCborMaxBytes)

	return IdentityProviderWrite{
		Alias:       m.Alias.ValueString(),
		Protocol:    walletProtocol,
		DisplayName: m.DisplayName.ValueString(),
		Enabled:     enabled,
		Config:      cfg,
	}
}

func getStr(ip *IdentityProviderRead, key string) types.String {
	return optString(ip.ConfigString(key))
}

func getInt(ip *IdentityProviderRead, key string) types.Int64 {
	v := ip.ConfigString(key)
	if v == "" {
		return types.Int64Null()
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return types.Int64Null()
	}
	return types.Int64Value(n)
}

func getBool(ip *IdentityProviderRead, key string) types.Bool {
	v := ip.ConfigString(key)
	if v == "" {
		return types.BoolNull()
	}
	return types.BoolValue(v == "true")
}

func getList(ctx context.Context, ip *IdentityProviderRead, key string) types.List {
	v := ip.ConfigString(key)
	if v == "" {
		return types.ListNull(types.StringType)
	}
	var elems []string
	if err := json.Unmarshal([]byte(v), &elems); err != nil {
		return types.ListNull(types.StringType)
	}
	l, diags := types.ListValueFrom(ctx, types.StringType, elems)
	if diags.HasError() {
		return types.ListNull(types.StringType)
	}
	return l
}

// applyRead overlays the server's view onto m, except for access_certificate_private_key: the admin API
// never returns a secret's value (only whether one is set), so that attribute is left exactly as it was
// in state/plan — never nulled out and never a source of drift.
func applyRead(ctx context.Context, m *walletIdentityProviderModel, ip *IdentityProviderRead) {
	m.ID = types.StringValue(ip.Alias)
	m.Alias = types.StringValue(ip.Alias)
	m.DisplayName = optString(ip.DisplayName)
	m.Enabled = types.BoolValue(ip.Enabled)

	m.ClientIDScheme = getStr(ip, "clientIdScheme")
	m.ClientIDHost = getStr(ip, "clientIdHost")
	m.AccessKeyRef = getStr(ip, "accessKeyRef")
	m.AccessCertificateChain = getStr(ip, "accessCertificateChain")
	// m.AccessCertificatePrivateKey intentionally untouched (write-only secret).
	m.RegistrationCertificate = getStr(ip, "registrationCertificate")
	m.InvocationScheme = getStr(ip, "invocationScheme")
	m.ResponseMode = getStr(ip, "responseMode")
	m.RequestURIMethod = getStr(ip, "requestUriMethod")
	m.TransactionTTLSeconds = getInt(ip, "transactionTtlSeconds")
	m.CredentialFormats = getList(ctx, ip, "credentialFormats")
	m.PidSdJwtVcts = getList(ctx, ip, "pid.sdJwtVcts")
	m.PidMdocDoctype = getStr(ip, "pid.mdocDoctype")
	m.PidRequestedClaims = getList(ctx, ip, "pid.requestedClaims")
	m.CustomCredentialQueries = getList(ctx, ip, "customCredentialQueries")
	m.TrustAnchors = getStr(ip, "trustAnchors")
	m.RevocationChecking = getStr(ip, "revocationChecking")
	m.StatusListRequired = getBool(ip, "statusList.required")
	m.StatusListOnUnavailable = getStr(ip, "statusList.onUnavailable")
	m.StatusListMaxCacheSeconds = getInt(ip, "statusList.maxCacheSeconds")
	m.StatusListAllowedHosts = getList(ctx, ip, "statusList.allowedHosts")
	m.SubjectStrategy = getStr(ip, "subject.strategy")
	m.SubjectAcknowledgeWeakSubject = getBool(ip, "subject.acknowledgeWeakSubject")
	m.MinimumLoa = getStr(ip, "minimumLoa")
	m.ClockSkewSeconds = getInt(ip, "clockSkewSeconds")
	m.AllowLegacyVcSdJwtTyp = getBool(ip, "allowLegacyVcSdJwtTyp")
	m.LimitsMaxJwtBytes = getInt(ip, "limits.maxJwtBytes")
	m.LimitsCborMaxDepth = getInt(ip, "limits.cborMaxDepth")
	m.LimitsCborMaxItems = getInt(ip, "limits.cborMaxItems")
	m.LimitsCborMaxBytes = getInt(ip, "limits.cborMaxBytes")
}

// --- CRUD ------------------------------------------------------------------------------------------------

func (r *walletIdentityProviderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m walletIdentityProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.CreateIdentityProvider(ctx, m.toWrite(ctx)); err != nil {
		resp.Diagnostics.AddError("Create wallet identity provider failed", err.Error())
		return
	}
	ip, nf, err := r.client.GetIdentityProvider(ctx, m.Alias.ValueString())
	if err != nil || nf {
		resp.Diagnostics.AddError("Read-after-create failed", fmt.Sprintf("err=%v notFound=%v", err, nf))
		return
	}
	applyRead(ctx, &m, ip)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *walletIdentityProviderResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m walletIdentityProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	ip, nf, err := r.client.GetIdentityProvider(ctx, m.Alias.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read wallet identity provider failed", err.Error())
		return
	}
	if nf {
		resp.State.RemoveResource(ctx)
		return
	}
	applyRead(ctx, &m, ip)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *walletIdentityProviderResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m walletIdentityProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateIdentityProvider(ctx, m.Alias.ValueString(), m.toWrite(ctx)); err != nil {
		resp.Diagnostics.AddError("Update wallet identity provider failed", err.Error())
		return
	}
	ip, _, err := r.client.GetIdentityProvider(ctx, m.Alias.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read-after-update failed", err.Error())
		return
	}
	applyRead(ctx, &m, ip)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *walletIdentityProviderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m walletIdentityProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteIdentityProvider(ctx, m.Alias.ValueString()); err != nil {
		resp.Diagnostics.AddError("Delete wallet identity provider failed", err.Error())
	}
}
