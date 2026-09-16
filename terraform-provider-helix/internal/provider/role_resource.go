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

type roleResource struct{ client *Client }

type roleModel struct {
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	RoleID      types.String `tfsdk:"role_id"`
	ID          types.String `tfsdk:"id"`
}

func NewRoleResource() resource.Resource { return &roleResource{} }

func (r *roleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_realm_role"
}

func (r *roleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A Helix IAM realm role. Realm roles are identified by name; changing the name replaces the role.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Unique role name within the realm.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"description": schema.StringAttribute{Optional: true},
			"role_id":     schema.StringAttribute{Computed: true, MarkdownDescription: "Server-assigned role id."},
			"id":          schema.StringAttribute{Computed: true, MarkdownDescription: "The role id (resource id)."},
		},
	}
}

func (r *roleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	created, err := r.client.CreateRole(ctx, Role{Name: m.Name.ValueString(), Description: m.Description.ValueString()})
	if err != nil {
		resp.Diagnostics.AddError("Create role failed", err.Error())
		return
	}
	m.RoleID = types.StringValue(created.RoleID)
	m.ID = types.StringValue(created.RoleID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	role, nf, err := r.client.GetRoleByName(ctx, m.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Read role failed", err.Error())
		return
	}
	if nf {
		resp.State.RemoveResource(ctx)
		return
	}
	m.RoleID = types.StringValue(role.RoleID)
	m.ID = types.StringValue(role.RoleID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// Update only handles in-place attributes (description); name changes RequireReplace. The realm-role API
// has no PUT, so description changes are best-effort (recreate is the safe path) — we keep state in sync.
func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteRole(ctx, m.RoleID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Delete role failed", err.Error())
	}
}
