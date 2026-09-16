/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// HelixProvider is the Terraform provider for Helix IAM (IAM-as-code).
type HelixProvider struct {
	version string
}

type helixProviderModel struct {
	BaseURL      types.String `tfsdk:"base_url"`
	Issuer       types.String `tfsdk:"issuer"`
	Realm        types.String `tfsdk:"realm"`
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &HelixProvider{version: version} }
}

func (p *HelixProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "helix"
	resp.Version = p.version
}

func (p *HelixProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage Helix IAM (realms, applications, roles) as code via the admin API.",
		Attributes: map[string]schema.Attribute{
			"issuer": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The realm issuer that mints the admin token, e.g. `https://idp.example.com/realms/master`. Falls back to `HELIX_ISSUER`.",
				Optional:            true,
			},
			"realm": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The realm to administer. Defaults to `master` or `HELIX_REALM`.",
			},
			"base_url": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Admin API origin if different from the issuer host. Falls back to `HELIX_BASE_URL`, else the issuer origin.",
			},
			"client_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "OAuth2 client id for the client-credentials admin token. Falls back to `HELIX_CLIENT_ID`.",
			},
			"client_secret": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "OAuth2 client secret. Falls back to `HELIX_CLIENT_SECRET`.",
			},
		},
	}
}

func (p *HelixProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg helixProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	issuer := firstNonEmpty(cfg.Issuer.ValueString(), os.Getenv("HELIX_ISSUER"))
	realm := firstNonEmpty(cfg.Realm.ValueString(), os.Getenv("HELIX_REALM"), "master")
	baseURL := firstNonEmpty(cfg.BaseURL.ValueString(), os.Getenv("HELIX_BASE_URL"), originOf(issuer))
	clientID := firstNonEmpty(cfg.ClientID.ValueString(), os.Getenv("HELIX_CLIENT_ID"))
	clientSecret := firstNonEmpty(cfg.ClientSecret.ValueString(), os.Getenv("HELIX_CLIENT_SECRET"))

	if issuer == "" {
		resp.Diagnostics.AddError("Missing issuer", "Set the `issuer` attribute or HELIX_ISSUER (e.g. https://idp.example.com/realms/master).")
		return
	}

	client := NewClient(baseURL, issuer, realm, clientID, clientSecret)
	resp.ResourceData = client
	resp.DataSourceData = client
}

func (p *HelixProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewApplicationResource,
		NewRoleResource,
	}
}

func (p *HelixProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// originOf returns scheme://host[:port] from a URL, or the input unchanged if it can't be parsed.
func originOf(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	// Cheap origin extraction without net/url to avoid an import cycle in tests; falls back to input.
	i := indexOfPath(rawURL)
	if i < 0 {
		return rawURL
	}
	return rawURL[:i]
}

// indexOfPath returns the index of the first '/' after the scheme "://", or -1.
func indexOfPath(s string) int {
	scheme := "://"
	si := indexOf(s, scheme)
	if si < 0 {
		return -1
	}
	rest := si + len(scheme)
	for i := rest; i < len(s); i++ {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
