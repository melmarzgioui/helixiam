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

// The verify-only / step-up settings (subject_strategy = "NONE", WalletProviderConfig's "verify.linkedProvider"
// and "verify.releasedClaims"): omitted when unset so the server default applies, encoded when set, read back
// exactly, no drift through create → read → no-op update, and an empty released-claims list refused (the server
// stores no key for it, which would read back as null and drift).

func TestToWrite_Verify_OmittedWhenUnset(t *testing.T) {
	w, diags := (&walletIdentityProviderModel{Alias: types.StringValue("w"), VerifyLinkedProvider: types.StringNull(),
		VerifyReleasedClaims: types.ListNull(types.StringType)}).toWrite(context.Background())
	if diags.HasError() {
		t.Fatalf("toWrite: %v", diags)
	}
	for _, key := range []string{"verify.linkedProvider", "verify.releasedClaims"} {
		if _, ok := w.Config[key]; ok {
			t.Fatalf("unset %s must be omitted, got %q", key, w.Config[key])
		}
	}
}

func TestToWrite_Verify_EncodesExplicitValues(t *testing.T) {
	ctx := context.Background()
	claims, _ := types.ListValueFrom(ctx, types.StringType, []string{"age_over_18", "nationalities"})
	w, diags := (&walletIdentityProviderModel{Alias: types.StringValue("v"), SubjectStrategy: types.StringValue("NONE"),
		VerifyLinkedProvider: types.StringValue("eudi-wallet"), VerifyReleasedClaims: claims}).toWrite(ctx)
	if diags.HasError() {
		t.Fatalf("toWrite: %v", diags)
	}
	if w.Config["subject.strategy"] != "NONE" || w.Config["verify.linkedProvider"] != "eudi-wallet" ||
		w.Config["verify.releasedClaims"] != `["age_over_18","nationalities"]` {
		t.Fatalf("unexpected verify config: %v", w.Config)
	}
}

func TestApplyRead_Verify_RoundTripsAndStaysNullWhenAbsent(t *testing.T) {
	ctx := context.Background()
	var absent walletIdentityProviderModel
	applyRead(ctx, &absent, &IdentityProviderRead{Alias: "w", Config: map[string]any{}})
	if !absent.VerifyLinkedProvider.IsNull() || !absent.VerifyReleasedClaims.IsNull() {
		t.Fatalf("absent verify settings must read back as null: %v %v", absent.VerifyLinkedProvider,
			absent.VerifyReleasedClaims)
	}
	var set walletIdentityProviderModel
	applyRead(ctx, &set, &IdentityProviderRead{Alias: "v", Config: map[string]any{"subject.strategy": "NONE",
		"verify.linkedProvider": "eudi-wallet", "verify.releasedClaims": `["age_over_18"]`}})
	want, _ := types.ListValueFrom(ctx, types.StringType, []string{"age_over_18"})
	if !set.VerifyLinkedProvider.Equal(types.StringValue("eudi-wallet")) || !set.VerifyReleasedClaims.Equal(want) {
		t.Fatalf("verify settings did not round-trip: %v %v", set.VerifyLinkedProvider, set.VerifyReleasedClaims)
	}
}

func TestWalletAttributePath_VerifyFieldErrors(t *testing.T) {
	for key, attr := range map[string]string{"config.verify.linkedProvider": "verify_linked_provider",
		"config.verify.releasedClaims": "verify_released_claims"} {
		p, ok := walletAttributePath(key)
		if !ok || !p.Equal(path.Root(attr)) {
			t.Fatalf("%s: expected %s, got %v (%v)", key, attr, p, ok)
		}
	}
}

func TestSchema_VerifyReleasedClaims_RefusesAnEmptyList(t *testing.T) {
	ctx := context.Background()
	empty, _ := types.ListValueFrom(ctx, types.StringType, []string{})
	resp := &validator.ListResponse{}
	notEmptyListValidator{}.ValidateList(ctx, validator.ListRequest{Path: path.Root("verify_released_claims"),
		ConfigValue: empty}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("an empty verify_released_claims must be refused")
	}
	attr := walletSchema(ctx, t).Attributes["verify_released_claims"]
	if attr == nil || !attr.IsOptional() {
		t.Fatal("verify_released_claims must be an optional attribute")
	}
	if a := walletSchema(ctx, t).Attributes["verify_linked_provider"]; a == nil || !a.IsOptional() {
		t.Fatal("verify_linked_provider must be an optional attribute")
	}
}

func TestResource_Verify_NoDrift(t *testing.T) {
	srv, _ := newFakeIdentityProviderServer(t)
	defer srv.Close()
	ctx := context.Background()
	r := &walletIdentityProviderResource{client: newWalletClient(srv.URL)}
	sch := walletSchema(ctx, t)
	claims, _ := types.ListValueFrom(ctx, types.StringType, []string{"age_over_18"})

	createResp := &resource.CreateResponse{State: newState(ctx, t, sch, &walletIdentityProviderModel{})}
	r.Create(ctx, resource.CreateRequest{Plan: newPlan(ctx, t, sch, &walletIdentityProviderModel{
		Alias:                types.StringValue("eudi-verify"),
		AccessKeyRef:         types.StringValue("software:gov/primary"),
		SubjectStrategy:      types.StringValue("NONE"),
		VerifyLinkedProvider: types.StringValue("eudi-wallet"),
		VerifyReleasedClaims: claims,
	})}, createResp)
	if createResp.Diagnostics.HasError() {
		t.Fatalf("create: %v", createResp.Diagnostics)
	}
	var afterCreate walletIdentityProviderModel
	createResp.State.Get(ctx, &afterCreate)
	if !afterCreate.VerifyLinkedProvider.Equal(types.StringValue("eudi-wallet")) ||
		!afterCreate.VerifyReleasedClaims.Equal(claims) {
		t.Fatalf("unexpected state after create: %v %v", afterCreate.VerifyLinkedProvider, afterCreate.VerifyReleasedClaims)
	}
	noOpResp := &resource.UpdateResponse{State: createResp.State}
	r.Update(ctx, resource.UpdateRequest{State: createResp.State, Plan: newPlan(ctx, t, sch, &afterCreate)}, noOpResp)
	if noOpResp.Diagnostics.HasError() {
		t.Fatalf("no-op update: %v", noOpResp.Diagnostics)
	}
	var afterNoOp walletIdentityProviderModel
	noOpResp.State.Get(ctx, &afterNoOp)
	if !afterNoOp.VerifyLinkedProvider.Equal(afterCreate.VerifyLinkedProvider) ||
		!afterNoOp.VerifyReleasedClaims.Equal(afterCreate.VerifyReleasedClaims) {
		t.Fatalf("a no-op plan must not drift the verify settings: before=%v after=%v", afterCreate, afterNoOp)
	}
}
