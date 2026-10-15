// Copyright 2026 HelixIAM contributors
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// The W3C Digital Credentials API settings (WalletProviderConfig's "dcApi.enabled", "dcApi.request" and
// "dcApi.expectedOrigins"): omitted when unset so the server default applies, encoded when set, read back
// exactly, and no drift through create → read → no-op update.

func TestToWrite_DcApi_OmittedWhenUnset(t *testing.T) {
	w, diags := (&walletIdentityProviderModel{Alias: types.StringValue("w"), DcApiEnabled: types.BoolNull(),
		DcApiRequest: types.StringNull(), DcApiExpectedOrigins: types.ListNull(types.StringType)}).toWrite(context.Background())
	if diags.HasError() {
		t.Fatalf("toWrite: %v", diags)
	}
	for _, key := range []string{"dcApi.enabled", "dcApi.request", "dcApi.expectedOrigins"} {
		if _, ok := w.Config[key]; ok {
			t.Fatalf("unset %s must be omitted, got %q", key, w.Config[key])
		}
	}
}

func TestToWrite_DcApi_EncodesExplicitValues(t *testing.T) {
	ctx := context.Background()
	origins, _ := types.ListValueFrom(ctx, types.StringType, []string{"https://login.example.eu", "https://id.example.eu"})
	w, diags := (&walletIdentityProviderModel{Alias: types.StringValue("w"), DcApiEnabled: types.BoolValue(true),
		DcApiRequest: types.StringValue("unsigned"), DcApiExpectedOrigins: origins}).toWrite(ctx)
	if diags.HasError() {
		t.Fatalf("toWrite: %v", diags)
	}
	if w.Config["dcApi.enabled"] != "true" || w.Config["dcApi.request"] != "unsigned" ||
		w.Config["dcApi.expectedOrigins"] != `["https://login.example.eu","https://id.example.eu"]` {
		t.Fatalf("unexpected dcApi config: %v", w.Config)
	}
}

func TestApplyRead_DcApi_RoundTripsAndStaysNullWhenAbsent(t *testing.T) {
	ctx := context.Background()
	var absent walletIdentityProviderModel
	applyRead(ctx, &absent, &IdentityProviderRead{Alias: "w", Config: map[string]any{}})
	if !absent.DcApiEnabled.IsNull() || !absent.DcApiRequest.IsNull() || !absent.DcApiExpectedOrigins.IsNull() {
		t.Fatalf("absent dcApi settings must read back as null: %v %v %v", absent.DcApiEnabled, absent.DcApiRequest,
			absent.DcApiExpectedOrigins)
	}
	var set walletIdentityProviderModel
	applyRead(ctx, &set, &IdentityProviderRead{Alias: "w", Config: map[string]any{"dcApi.enabled": "false",
		"dcApi.request": "signed", "dcApi.expectedOrigins": `["https://login.example.eu"]`}})
	want, _ := types.ListValueFrom(ctx, types.StringType, []string{"https://login.example.eu"})
	if !set.DcApiEnabled.Equal(types.BoolValue(false)) || !set.DcApiRequest.Equal(types.StringValue("signed")) ||
		!set.DcApiExpectedOrigins.Equal(want) {
		t.Fatalf("dcApi settings did not round-trip: %v %v %v", set.DcApiEnabled, set.DcApiRequest, set.DcApiExpectedOrigins)
	}
}

func TestWalletAttributePath_DcApiFieldErrors(t *testing.T) {
	for key, attr := range map[string]string{"config.dcApi.enabled": "dc_api_enabled",
		"config.dcApi.request": "dc_api_request", "config.dcApi.expectedOrigins": "dc_api_expected_origins"} {
		p, ok := walletAttributePath(key)
		if !ok || !p.Equal(path.Root(attr)) {
			t.Fatalf("%s: expected %s, got %v (%v)", key, attr, p, ok)
		}
	}
}

func TestResource_DcApi_NoDrift(t *testing.T) {
	srv, _ := newFakeIdentityProviderServer(t)
	defer srv.Close()
	ctx := context.Background()
	r := &walletIdentityProviderResource{client: newWalletClient(srv.URL)}
	sch := walletSchema(ctx, t)
	origins, _ := types.ListValueFrom(ctx, types.StringType, []string{"https://login.example.eu"})

	createResp := &resource.CreateResponse{State: newState(ctx, t, sch, &walletIdentityProviderModel{})}
	r.Create(ctx, resource.CreateRequest{Plan: newPlan(ctx, t, sch, &walletIdentityProviderModel{
		Alias:                types.StringValue("dc-api-wallet"),
		AccessKeyRef:         types.StringValue("software:gov/primary"),
		DcApiEnabled:         types.BoolValue(true),
		DcApiExpectedOrigins: origins,
		// dc_api_request left unset.
	})}, createResp)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("create: %v", createResp.Diagnostics)
	}
	var afterCreate walletIdentityProviderModel
	createResp.State.Get(ctx, &afterCreate)
	if !afterCreate.DcApiEnabled.Equal(types.BoolValue(true)) || !afterCreate.DcApiRequest.IsNull() ||
		!afterCreate.DcApiExpectedOrigins.Equal(origins) {
		t.Fatalf("unexpected state after create: %v %v %v", afterCreate.DcApiEnabled, afterCreate.DcApiRequest,
			afterCreate.DcApiExpectedOrigins)
	}

	noOpResp := &resource.UpdateResponse{State: createResp.State}
	r.Update(ctx, resource.UpdateRequest{State: createResp.State, Plan: newPlan(ctx, t, sch, &afterCreate)}, noOpResp)
	if noOpResp.Diagnostics.HasError() {
		t.Fatalf("no-op update: %v", noOpResp.Diagnostics)
	}
	var afterNoOp walletIdentityProviderModel
	noOpResp.State.Get(ctx, &afterNoOp)
	if !afterNoOp.DcApiEnabled.Equal(afterCreate.DcApiEnabled) || !afterNoOp.DcApiRequest.Equal(afterCreate.DcApiRequest) ||
		!afterNoOp.DcApiExpectedOrigins.Equal(afterCreate.DcApiExpectedOrigins) {
		t.Fatalf("a no-op plan must not drift the dcApi settings: before=%v after=%v", afterCreate, afterNoOp)
	}
}
