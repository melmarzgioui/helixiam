// Copyright 2026 HelixIAM contributors
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// The trusted-list references (WalletProviderConfig's "trustedLists.sources" and "trustedLists.serviceTypes"):
// omitted when unset, encoded when set, read back exactly, refused when empty, and no drift through
// create → read → no-op update.

func TestToWrite_TrustedLists_OmittedWhenUnset(t *testing.T) {
	w, diags := (&walletIdentityProviderModel{Alias: types.StringValue("w"), TrustedLists: types.ListNull(types.StringType),
		TrustedListServiceTypes: types.ListNull(types.StringType)}).toWrite(context.Background())
	if diags.HasError() {
		t.Fatalf("toWrite: %v", diags)
	}
	for _, key := range []string{"trustedLists.sources", "trustedLists.serviceTypes"} {
		if _, ok := w.Config[key]; ok {
			t.Fatalf("unset %s must be omitted, got %q", key, w.Config[key])
		}
	}
}

func TestToWrite_TrustedLists_EncodesExplicitValues(t *testing.T) {
	ctx := context.Background()
	sources, _ := types.ListValueFrom(ctx, types.StringType, []string{"eudi-pid-providers", "nl-pid"})
	types_, _ := types.ListValueFrom(ctx, types.StringType, []string{"http://uri.etsi.org/19602/SvcType/PID/Issuance"})
	w, diags := (&walletIdentityProviderModel{Alias: types.StringValue("w"), TrustedLists: sources,
		TrustedListServiceTypes: types_}).toWrite(ctx)
	if diags.HasError() {
		t.Fatalf("toWrite: %v", diags)
	}
	if w.Config["trustedLists.sources"] != `["eudi-pid-providers","nl-pid"]` ||
		w.Config["trustedLists.serviceTypes"] != `["http://uri.etsi.org/19602/SvcType/PID/Issuance"]` {
		t.Fatalf("unexpected trustedLists config: %v", w.Config)
	}
}

func TestApplyRead_TrustedLists_RoundTripsAndStaysNullWhenAbsent(t *testing.T) {
	ctx := context.Background()
	var absent walletIdentityProviderModel
	applyRead(ctx, &absent, &IdentityProviderRead{Alias: "w", Config: map[string]any{}})
	if !absent.TrustedLists.IsNull() || !absent.TrustedListServiceTypes.IsNull() {
		t.Fatalf("absent trusted lists must read back as null: %v %v", absent.TrustedLists, absent.TrustedListServiceTypes)
	}
	var set walletIdentityProviderModel
	applyRead(ctx, &set, &IdentityProviderRead{Alias: "w", Config: map[string]any{
		"trustedLists.sources": `["eudi-pid-providers"]`, "trustedLists.serviceTypes": `["urn:x"]`}})
	want, _ := types.ListValueFrom(ctx, types.StringType, []string{"eudi-pid-providers"})
	wantTypes, _ := types.ListValueFrom(ctx, types.StringType, []string{"urn:x"})
	if !set.TrustedLists.Equal(want) || !set.TrustedListServiceTypes.Equal(wantTypes) {
		t.Fatalf("trusted lists did not round-trip: %v %v", set.TrustedLists, set.TrustedListServiceTypes)
	}
}

func TestWalletAttributePath_TrustedListFieldErrors(t *testing.T) {
	for key, attr := range map[string]string{"config.trustedLists.sources": "trusted_lists",
		"config.trustedLists.serviceTypes": "trusted_list_service_types"} {
		p, ok := walletAttributePath(key)
		if !ok || !p.Equal(path.Root(attr)) {
			t.Fatalf("%s: expected %s, got %v (%v)", key, attr, p, ok)
		}
	}
}

// An empty list is refused at plan time: the server stores nothing for it, so it would read back as
// null and drift.
func TestTrustedLists_EmptyListIsRefused(t *testing.T) {
	ctx := context.Background()
	empty, _ := types.ListValueFrom(ctx, types.StringType, []string{})
	resp := &validator.ListResponse{}
	notEmptyListValidator{}.ValidateList(ctx, validator.ListRequest{Path: path.Root("trusted_lists"),
		ConfigValue: empty}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("an empty trusted_lists must be refused")
	}
	for _, v := range []types.List{types.ListNull(types.StringType), types.ListUnknown(types.StringType)} {
		ok := &validator.ListResponse{}
		notEmptyListValidator{}.ValidateList(ctx, validator.ListRequest{Path: path.Root("trusted_lists"),
			ConfigValue: v}, ok)
		if ok.Diagnostics.HasError() {
			t.Fatalf("null/unknown must pass: %v", ok.Diagnostics)
		}
	}
	sch := walletSchema(ctx, t)
	for _, attr := range []string{"trusted_lists", "trusted_list_service_types"} {
		a, d := sch.AttributeAtPath(ctx, path.Root(attr))
		if d.HasError() || !a.IsOptional() {
			t.Fatalf("%s must be an optional attribute: %v", attr, d)
		}
	}
}

func TestResource_TrustedLists_NoDrift(t *testing.T) {
	srv, _ := newFakeIdentityProviderServer(t)
	defer srv.Close()
	ctx := context.Background()
	r := &walletIdentityProviderResource{client: newWalletClient(srv.URL)}
	sch := walletSchema(ctx, t)
	sources, _ := types.ListValueFrom(ctx, types.StringType, []string{"eudi-pid-providers"})

	createResp := &resource.CreateResponse{State: newState(ctx, t, sch, &walletIdentityProviderModel{})}
	r.Create(ctx, resource.CreateRequest{Plan: newPlan(ctx, t, sch, &walletIdentityProviderModel{
		Alias:        types.StringValue("tl-wallet"),
		AccessKeyRef: types.StringValue("software:gov/primary"),
		TrustedLists: sources,
		// trusted_list_service_types left unset.
	})}, createResp)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("create: %v", createResp.Diagnostics)
	}
	var afterCreate walletIdentityProviderModel
	createResp.State.Get(ctx, &afterCreate)
	if !afterCreate.TrustedLists.Equal(sources) || !afterCreate.TrustedListServiceTypes.IsNull() {
		t.Fatalf("unexpected state after create: %v %v", afterCreate.TrustedLists, afterCreate.TrustedListServiceTypes)
	}

	noOpResp := &resource.UpdateResponse{State: createResp.State}
	r.Update(ctx, resource.UpdateRequest{State: createResp.State, Plan: newPlan(ctx, t, sch, &afterCreate)}, noOpResp)
	if noOpResp.Diagnostics.HasError() {
		t.Fatalf("no-op update: %v", noOpResp.Diagnostics)
	}
	var afterNoOp walletIdentityProviderModel
	noOpResp.State.Get(ctx, &afterNoOp)
	if !afterNoOp.TrustedLists.Equal(afterCreate.TrustedLists) ||
		!afterNoOp.TrustedListServiceTypes.Equal(afterCreate.TrustedListServiceTypes) {
		t.Fatalf("a no-op plan must not drift the trusted lists: before=%v after=%v", afterCreate, afterNoOp)
	}
}
