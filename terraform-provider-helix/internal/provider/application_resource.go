/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type applicationResource struct{ client *Client }

type applicationModel struct {
	Name          types.String `tfsdk:"name"`
	DisplayName   types.String `tfsdk:"display_name"`
	Description   types.String `tfsdk:"description"`
	SubjectClaim  types.String `tfsdk:"subject_claim"`
	AuthFlowAlias types.String `tfsdk:"auth_flow_alias"`
	Enabled       types.Bool   `tfsdk:"enabled"`
	ID            types.String `tfsdk:"id"`
}

func NewApplicationResource() resource.Resource { return &applicationResource{} }

func (r *applicationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_application"
}

func (r *applicationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A Helix IAM Application (Service Provider) — the protocol-agnostic parent of an OIDC client / SAML relying party.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Unique application name within the realm (the natural key).",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"display_name":    schema.StringAttribute{Optional: true, MarkdownDescription: "Human-friendly name shown in the console."},
			"description":     schema.StringAttribute{Optional: true},
			"subject_claim":   schema.StringAttribute{Optional: true, MarkdownDescription: "Claim used as the token subject for this app (e.g. `email`)."},
			"auth_flow_alias": schema.StringAttribute{Optional: true, MarkdownDescription: "Authentication flow bound to this app."},
			"enabled":         schema.BoolAttribute{Optional: true, Computed: true, MarkdownDescription: "Whether the application is enabled (default true)."},
			"id":              schema.StringAttribute{Computed: true, MarkdownDescription: "The application name (resource id)."},
		},
	}
}

func (r *applicationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (m applicationModel) toApp() Application {
	enabled := true
	if !m.Enabled.IsNull() && !m.Enabled.IsUnknown() {
		enabled = m.Enabled.ValueBool()
	}
	return Application{
		Name:          m.Name.ValueString(),
		DisplayName:   m.DisplayName.ValueString(),
		Description:   m.Description.ValueString(),
		SubjectClaim:  m.SubjectClaim.ValueString(),
		AuthFlowAlias: m.AuthFlowAlias.ValueString(),
		Enabled:       enabled,
	}
}

func applyApp(m *applicationModel, app *Application) {
	m.ID = types.StringValue(app.Name)
	m.Name = types.StringValue(app.Name)
	m.Enabled = types.BoolValue(app.Enabled)
	m.DisplayName = optString(app.DisplayName)
	m.Description = optString(app.Description)
	m.SubjectClaim = optString(app.SubjectClaim)
	m.AuthFlowAlias = optString(app.AuthFlowAlias)
}

func optString(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

func (r *applicationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m applicationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.CreateApplication(ctx, m.toApp()); err != nil {
		resp.Diagnostics.AddError("Create application failed", err.Error())
		return
	}
	app, nf, err := r.client.GetApplication(ctx, m.Name.ValueString())
	if err != nil || nf {
		resp.Diagnostics.AddError("Read-after-create failed", fmt.Sprintf("err=%v notFound=%v", err, nf))
		return
	}
	applyApp(&m, app)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *applicationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m applicationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	app, nf, err := r.client.GetApplication(ctx, m.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read application failed", err.Error())
		return
	}
	if nf {
		resp.State.RemoveResource(ctx)
		return
	}
	applyApp(&m, app)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *applicationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m applicationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.UpdateApplication(ctx, m.toApp()); err != nil {
		resp.Diagnostics.AddError("Update application failed", err.Error())
		return
	}
	app, _, err := r.client.GetApplication(ctx, m.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read-after-update failed", err.Error())
		return
	}
	applyApp(&m, app)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *applicationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m applicationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteApplication(ctx, m.Name.ValueString()); err != nil {
		resp.Diagnostics.AddError("Delete application failed", err.Error())
	}
}
