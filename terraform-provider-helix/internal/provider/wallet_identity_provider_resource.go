/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// walletProtocol is the canonical protocol value the admin API documents for an EUDI wallet connection
// (docs/eudi-wallet.md §2.4). "openid4vp" and "wallet" are accepted aliases server-side
// (FederationProviderFactory.isWallet) but the resource always writes the canonical one.
const walletProtocol = "eudi-wallet"

// accessCertificatePrivateKeyConfigKey is the one secret this resource writes (ProviderSecretKeys.WALLET).
// clearAccessCertificatePrivateKeyFlag is the admin API's "clear<Key>" control flag for it
// (ProviderSecretKeys.clearFlag): sending it with value "true" removes a stored secret outright, as
// opposed to simply not mentioning the key, which keeps whatever is already stored.
const (
	accessCertificatePrivateKeyConfigKey = "accessCertificatePrivateKey"
	clearAccessCertificatePrivateKeyFlag = "clearAccessCertificatePrivateKey"
)

// walletConfigAttr maps a wire config key (dotted for nested settings, as WalletProviderConfig stores it)
// to this resource's Terraform attribute name. Used to turn the admin API's per-field validation errors
// ({@code config.<key>}, WalletConfigValidator.asAdminFields) into attribute-level diagnostics. Keys the
// resource does not expose (accessCertificateKeyRef, subjectPepper) are intentionally absent: an error on
// one of those falls back to a plain (non-attribute) diagnostic.
var walletConfigAttr = map[string]string{
	"clientIdScheme":                     "client_id_scheme",
	"clientIdHost":                       "client_id_host",
	"accessKeyRef":                       "access_key_ref",
	"accessCertificateChain":             "access_certificate_chain",
	accessCertificatePrivateKeyConfigKey: "access_certificate_private_key",
	"registrationCertificate":            "registration_certificate",
	"invocationScheme":                   "invocation_scheme",
	"responseMode":                       "response_mode",
	"requestUriMethod":                   "request_uri_method",
	"transactionTtlSeconds":              "transaction_ttl_seconds",
	"credentialFormats":                  "credential_formats",
	"pid.sdJwtVcts":                      "pid_sd_jwt_vcts",
	"pid.mdocDoctype":                    "pid_mdoc_doctype",
	"pid.requestedClaims":                "pid_requested_claims",
	"customCredentialQueries":            "custom_credential_queries",
	"trustAnchors":                       "trust_anchors",
	"revocationChecking":                 "revocation_checking",
	"statusList.required":                "status_list_required",
	"statusList.onUnavailable":           "status_list_on_unavailable",
	"statusList.maxCacheSeconds":         "status_list_max_cache_seconds",
	"statusList.allowedHosts":            "status_list_allowed_hosts",
	"subject.strategy":                   "subject_strategy",
	"subject.acknowledgeWeakSubject":     "subject_acknowledge_weak_subject",
	"minimumLoa":                         "minimum_loa",
	"clockSkewSeconds":                   "clock_skew_seconds",
	"allowLegacyVcSdJwtTyp":              "allow_legacy_vc_sd_jwt_typ",
	"limits.maxJwtBytes":                 "limits_max_jwt_bytes",
	"limits.cborMaxDepth":                "limits_cbor_max_depth",
	"limits.cborMaxItems":                "limits_cbor_max_items",
	"limits.cborMaxBytes":                "limits_cbor_max_bytes",
	"dcql.trustedAuthorities":            "dcql_trusted_authorities",
}

// walletAttributePath maps one admin API field-error name (WalletConfigValidator.asAdminFields: "alias"
// and "displayName" bare, every config key as "config.<key>") to this resource's attribute path. The
// second return value is false when the field is not one of this resource's attributes (an unexposed
// config key, or a field this resource does not recognise), in which case the caller falls back to a
// plain diagnostic instead of an attribute one.
func walletAttributePath(field string) (path.Path, bool) {
	switch field {
	case "alias":
		return path.Root("alias"), true
	case "displayName":
		return path.Root("display_name"), true
	}
	if key, ok := strings.CutPrefix(field, "config."); ok {
		if attr, ok := walletConfigAttr[key]; ok {
			return path.Root(attr), true
		}
	}
	return path.Path{}, false
}

// addClientError reports an error from a Client call as Terraform diagnostics: an *AdminError carrying
// field errors (a 400 from WalletConfigValidator, surfaced by AdminValidationAdvice) becomes one
// AddAttributeError per field whose name this resource recognises (walletAttributePath), falling back to
// a plain AddError for the rest; any other error (including an *AdminError with no field errors) becomes
// a single plain AddError, as before.
func addClientError(diags *diag.Diagnostics, summary string, err error) {
	var ae *AdminError
	if errors.As(err, &ae) && len(ae.FieldErrors) > 0 {
		fields := make([]string, 0, len(ae.FieldErrors))
		for field := range ae.FieldErrors {
			fields = append(fields, field)
		}
		sort.Strings(fields)
		for _, field := range fields {
			message := ae.FieldErrors[field]
			if p, ok := walletAttributePath(field); ok {
				diags.AddAttributeError(p, summary, message)
			} else {
				diags.AddError(fmt.Sprintf("%s: %s", summary, field), message)
			}
		}
		return
	}
	diags.AddError(summary, err.Error())
}

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
	DcqlTrustedAuthorities        types.Bool   `tfsdk:"dcql_trusted_authorities"`

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
			"applies and a `terraform plan` never shows drift for it.\n\n" +
			"**`access_certificate_private_key` is write-only, but Terraform state is not encrypted.** The admin " +
			"API never returns a secret's value, only whether one is set (so Terraform cannot read it back — it " +
			"keeps whatever is in state), but what you write into this attribute is stored in plaintext in the " +
			"Terraform state file, same as any other non-sensitive attribute; `Sensitive: true` only redacts it " +
			"from CLI output and logs, it does not encrypt state. Keep state encrypted at rest or in a remote " +
			"backend that encrypts it (e.g. Terraform Cloud, an S3 backend with SSE and restricted access) " +
			"whenever this attribute is set. **Prefer `access_key_ref`** (a key imported via " +
			"`/admin/realms/{realm}/verifier-keys`, never written to Terraform state at all) for anything beyond " +
			"a dev instance: `access_certificate_private_key` is accepted only when the server runs in the `dev` " +
			"deployment profile (WalletConfigValidator) and is refused in every other profile. Removing the " +
			"`access_certificate_private_key` line from your configuration while state still has a value sends " +
			"`clearAccessCertificatePrivateKey=true`, so the stored secret is actually removed, not just left " +
			"unmanaged; this is never sent when state has no value for it (for example right after `terraform " +
			"import`), since there is nothing to clear.\n\n" +
			"**The realm is the provider's, not the resource's.** A connection is created in the realm the " +
			"provider block is configured for (`realm`/`HELIX_REALM`); changing that on the provider does not " +
			"move existing connections — Terraform plans to create them again in the new realm, and the ones in " +
			"the old realm are left behind, unmanaged.",
		Attributes: map[string]schema.Attribute{
			"alias": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Unique alias for this connection within the realm (the natural key).",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"display_name": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Label shown in the console and on the login page. If set, must not be empty — omit the attribute instead of setting `\"\"`.",
				Validators:          []validator.String{notEmptyStringValidator{}},
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Whether the connection is offered at login (default true).",
				PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},

			"client_id_scheme":                 schema.StringAttribute{Optional: true, MarkdownDescription: "`client_id` prefix scheme (OpenID4VP §5.9.3): `x509_hash` (default) or `x509_san_dns`."},
			"client_id_host":                   schema.StringAttribute{Optional: true, MarkdownDescription: "DNS host asserted as `client_id`; required, and must be a SAN of the access certificate, when `client_id_scheme = \"x509_san_dns\"`."},
			"access_key_ref":                   schema.StringAttribute{Optional: true, MarkdownDescription: "**Recommended.** Reference to a realm signing key imported via `/admin/realms/{realm}/verifier-keys` (e.g. `software:gov/primary`) and used as the verifier's access key; the private key itself is never written to Terraform state. Required unless the dev-only `access_certificate_private_key` is used instead."},
			"access_certificate_chain":         schema.StringAttribute{Optional: true, MarkdownDescription: "PEM certificate chain (leaf first, no root) for the access key. With `access_key_ref` it must equal that key's own chain; it is the source of the request object's `x5c` only with `access_certificate_private_key`."},
			"access_certificate_private_key":   schema.StringAttribute{Optional: true, Sensitive: true, MarkdownDescription: "A raw PEM private key, as an alternative to `access_key_ref`. The server (`WalletConfigValidator`) accepts this only in the `dev` deployment profile and refuses it everywhere else — prefer `access_key_ref` outside of a dev instance. Never returned by the admin API (write-only); **stored in plaintext in Terraform state** despite being `Sensitive` (that flag only redacts CLI output and logs) — keep state encrypted or remote. See the resource description for the exact drift and clear-on-removal semantics."},
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
			"dcql_trusted_authorities":         schema.BoolAttribute{Optional: true, MarkdownDescription: "Whether the DCQL query carries the `aki` Trusted Authorities Query (HAIP §5, OpenID4VP §6.1.1.1) naming `trust_anchors`' key identifiers. Left unset, the server defaults this to on under the HAIP profile (`client_id_scheme = \"x509_hash\"` with `response_mode = \"direct_post.jwt\"`) and off otherwise. Setting it to `true` requires every configured trust anchor to carry a SubjectKeyIdentifier extension — the server never guesses one — or the write is refused."},

			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The connection alias (resource id).",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

// notEmptyStringValidator refuses an explicit "" (empty string isn't the same as unset: Optional means
// "may be absent", not "may be blank"). Null and unknown values pass — unset is how you omit the
// attribute, and an unknown value cannot be checked yet.
type notEmptyStringValidator struct{}

func (notEmptyStringValidator) Description(context.Context) string {
	return "value must not be an empty string"
}

func (v notEmptyStringValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (notEmptyStringValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if req.ConfigValue.ValueString() == "" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value",
			"This attribute must not be an empty string; omit it instead of setting it to \"\".")
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

// putList JSON-encodes a list attribute into cfg[key], or omits the key when v is null (the attribute is
// genuinely unset). An unknown value (its value depends on something not yet known at apply time — it
// should not normally reach here, since this is a plain Optional attribute, not Computed) and an invalid
// element (e.g. a null element, which attr.Value permits) are reported as an attribute diagnostic instead
// of being silently dropped: the write would otherwise go out missing data the configuration asked for.
func putList(ctx context.Context, diags *diag.Diagnostics, attr, key string, cfg map[string]string, v types.List) {
	if v.IsNull() {
		return
	}
	if v.IsUnknown() {
		diags.AddAttributeError(path.Root(attr), "Unknown value",
			"The value is not known at apply time, so it cannot be written to the admin API.")
		return
	}
	var elems []string
	if d := v.ElementsAs(ctx, &elems, false); d.HasError() {
		diags.Append(d...)
		return
	}
	b, err := json.Marshal(elems)
	if err != nil {
		diags.AddAttributeError(path.Root(attr), "Could not encode value", err.Error())
		return
	}
	cfg[key] = string(b)
}

// toWrite builds the admin API request body. Any attribute left null/unknown in the model is left out of
// config, so the server's own default (never stored) applies and a later Read sees the same absence. The
// returned diagnostics come only from the list attributes (putList); callers must check HasError() before
// using the write.
func (m *walletIdentityProviderModel) toWrite(ctx context.Context) (IdentityProviderWrite, diag.Diagnostics) {
	var diags diag.Diagnostics
	enabled := true
	if !m.Enabled.IsNull() && !m.Enabled.IsUnknown() {
		enabled = m.Enabled.ValueBool()
	}
	cfg := map[string]string{}
	putStr(cfg, "clientIdScheme", m.ClientIDScheme)
	putStr(cfg, "clientIdHost", m.ClientIDHost)
	putStr(cfg, "accessKeyRef", m.AccessKeyRef)
	putStr(cfg, "accessCertificateChain", m.AccessCertificateChain)
	putStr(cfg, accessCertificatePrivateKeyConfigKey, m.AccessCertificatePrivateKey)
	putStr(cfg, "registrationCertificate", m.RegistrationCertificate)
	putStr(cfg, "invocationScheme", m.InvocationScheme)
	putStr(cfg, "responseMode", m.ResponseMode)
	putStr(cfg, "requestUriMethod", m.RequestURIMethod)
	putInt(cfg, "transactionTtlSeconds", m.TransactionTTLSeconds)
	putList(ctx, &diags, "credential_formats", "credentialFormats", cfg, m.CredentialFormats)
	putList(ctx, &diags, "pid_sd_jwt_vcts", "pid.sdJwtVcts", cfg, m.PidSdJwtVcts)
	putStr(cfg, "pid.mdocDoctype", m.PidMdocDoctype)
	putList(ctx, &diags, "pid_requested_claims", "pid.requestedClaims", cfg, m.PidRequestedClaims)
	putList(ctx, &diags, "custom_credential_queries", "customCredentialQueries", cfg, m.CustomCredentialQueries)
	putStr(cfg, "trustAnchors", m.TrustAnchors)
	putStr(cfg, "revocationChecking", m.RevocationChecking)
	putBool(cfg, "statusList.required", m.StatusListRequired)
	putStr(cfg, "statusList.onUnavailable", m.StatusListOnUnavailable)
	putInt(cfg, "statusList.maxCacheSeconds", m.StatusListMaxCacheSeconds)
	putList(ctx, &diags, "status_list_allowed_hosts", "statusList.allowedHosts", cfg, m.StatusListAllowedHosts)
	putStr(cfg, "subject.strategy", m.SubjectStrategy)
	putBool(cfg, "subject.acknowledgeWeakSubject", m.SubjectAcknowledgeWeakSubject)
	putStr(cfg, "minimumLoa", m.MinimumLoa)
	putInt(cfg, "clockSkewSeconds", m.ClockSkewSeconds)
	putBool(cfg, "allowLegacyVcSdJwtTyp", m.AllowLegacyVcSdJwtTyp)
	putInt(cfg, "limits.maxJwtBytes", m.LimitsMaxJwtBytes)
	putInt(cfg, "limits.cborMaxDepth", m.LimitsCborMaxDepth)
	putInt(cfg, "limits.cborMaxItems", m.LimitsCborMaxItems)
	putInt(cfg, "limits.cborMaxBytes", m.LimitsCborMaxBytes)
	putBool(cfg, "dcql.trustedAuthorities", m.DcqlTrustedAuthorities)

	if diags.HasError() {
		return IdentityProviderWrite{}, diags
	}
	return IdentityProviderWrite{
		Alias:       m.Alias.ValueString(),
		Protocol:    walletProtocol,
		DisplayName: m.DisplayName.ValueString(),
		Enabled:     enabled,
		Config:      cfg,
	}, diags
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
	m.DcqlTrustedAuthorities = getBool(ip, "dcql.trustedAuthorities")
}

// --- CRUD ------------------------------------------------------------------------------------------------

func (r *walletIdentityProviderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m walletIdentityProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	write, diags := m.toWrite(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.CreateIdentityProvider(ctx, write); err != nil {
		addClientError(&resp.Diagnostics, "Create wallet identity provider failed", err)
		return
	}
	ip, nf, err := r.client.GetIdentityProvider(ctx, m.Alias.ValueString())
	if err != nil {
		addClientError(&resp.Diagnostics, "Read-after-create failed", err)
		return
	}
	if nf {
		resp.Diagnostics.AddError("Read-after-create failed",
			fmt.Sprintf("the connection %q was not found immediately after being created", m.Alias.ValueString()))
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
		addClientError(&resp.Diagnostics, "Read wallet identity provider failed", err)
		return
	}
	if nf {
		resp.State.RemoveResource(ctx)
		return
	}
	applyRead(ctx, &m, ip)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// Update sends clearAccessCertificatePrivateKeyFlag=true exactly when the prior state had a value for
// access_certificate_private_key and the plan no longer does: declarative removal means removal, not
// merely "Terraform stops managing it while the server keeps the old value" (the admin API's default
// contract when a secret key is simply absent from a write). It is never sent when the prior state had no
// value — e.g. right after `terraform import`, where there is nothing to clear and no way to know the
// server even has a secret set.
func (r *walletIdentityProviderResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var prior walletIdentityProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	var m walletIdentityProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	write, diags := m.toWrite(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if clearsAccessCertificatePrivateKey(prior.AccessCertificatePrivateKey, m.AccessCertificatePrivateKey) {
		write.Config[clearAccessCertificatePrivateKeyFlag] = "true"
	}
	if err := r.client.UpdateIdentityProvider(ctx, m.Alias.ValueString(), write); err != nil {
		addClientError(&resp.Diagnostics, "Update wallet identity provider failed", err)
		return
	}
	ip, _, err := r.client.GetIdentityProvider(ctx, m.Alias.ValueString())
	if err != nil {
		addClientError(&resp.Diagnostics, "Read-after-update failed", err)
		return
	}
	applyRead(ctx, &m, ip)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// clearsAccessCertificatePrivateKey reports whether an update is removing a previously-set value for
// access_certificate_private_key (prior state non-null, planned value null). A transition from null to
// null (never set, or already cleared) and from one non-null value to another (a rotation, carried by the
// new value itself) are both false — only an explicit removal clears.
func clearsAccessCertificatePrivateKey(prior, planned types.String) bool {
	return !prior.IsNull() && !prior.IsUnknown() && planned.IsNull()
}

func (r *walletIdentityProviderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m walletIdentityProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteIdentityProvider(ctx, m.Alias.ValueString()); err != nil {
		addClientError(&resp.Diagnostics, "Delete wallet identity provider failed", err)
	}
}
