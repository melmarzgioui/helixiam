/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package provider

import (
	"context"
	"os"
	"testing"
)

// TestLiveCRUD exercises the client against a REAL running Helix publisher. It is gated on
// HELIX_LIVE_BASEURL so it is skipped in normal `go test`. Run it with:
//
//	HELIX_LIVE_BASEURL=http://localhost:8083 go test ./internal/provider -run TestLiveCRUD -v
//
// In a dev instance with admin auth open (helix.admin.dev-open=true) no client credentials are
// needed; otherwise also set HELIX_CLIENT_ID/HELIX_CLIENT_SECRET.
func TestLiveCRUD(t *testing.T) {
	base := os.Getenv("HELIX_LIVE_BASEURL")
	if base == "" {
		t.Skip("set HELIX_LIVE_BASEURL to run the live CRUD test")
	}
	realm := getenv("HELIX_REALM", "master")
	c := NewClient(base, base+"/realms/"+realm, realm, os.Getenv("HELIX_CLIENT_ID"), os.Getenv("HELIX_CLIENT_SECRET"))
	ctx := context.Background()

	// --- Application: create → read → update → delete ---
	const appName = "tf-live-app"
	_ = c.DeleteApplication(ctx, appName) // best-effort pre-clean
	if err := c.CreateApplication(ctx, Application{Name: appName, DisplayName: "TF Live", Enabled: true}); err != nil {
		t.Fatalf("create app: %v", err)
	}
	app, nf, err := c.GetApplication(ctx, appName)
	if err != nil || nf {
		t.Fatalf("get app: err=%v nf=%v", err, nf)
	}
	if app.DisplayName != "TF Live" {
		t.Fatalf("expected displayName 'TF Live', got %q", app.DisplayName)
	}
	if err := c.UpdateApplication(ctx, Application{Name: appName, DisplayName: "TF Live v2", Enabled: true}); err != nil {
		t.Fatalf("update app: %v", err)
	}
	app, _, _ = c.GetApplication(ctx, appName)
	if app.DisplayName != "TF Live v2" {
		t.Fatalf("expected updated displayName 'TF Live v2', got %q", app.DisplayName)
	}
	if err := c.DeleteApplication(ctx, appName); err != nil {
		t.Fatalf("delete app: %v", err)
	}
	if _, nf, _ := c.GetApplication(ctx, appName); !nf {
		t.Fatalf("expected app gone after delete")
	}

	// --- Realm role: create → read → delete ---
	const roleName = "tf-live-role"
	created, err := c.CreateRole(ctx, Role{Name: roleName, Description: "tf live"})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if created.RoleID == "" {
		t.Fatalf("expected a server-assigned role id")
	}
	got, nf, err := c.GetRoleByName(ctx, roleName)
	if err != nil || nf {
		t.Fatalf("get role: err=%v nf=%v", err, nf)
	}
	if got.RoleID != created.RoleID {
		t.Fatalf("role id mismatch: %q vs %q", got.RoleID, created.RoleID)
	}
	if err := c.DeleteRole(ctx, created.RoleID); err != nil {
		t.Fatalf("delete role: %v", err)
	}
	if _, nf, _ := c.GetRoleByName(ctx, roleName); !nf {
		t.Fatalf("expected role gone after delete")
	}
	t.Logf("live CRUD OK: application + realm role created, read, updated, deleted against %s", base)
}

// TestLiveWalletIdentityProviderCRUD exercises the EUDI wallet identity-provider connection against a
// REAL running Helix publisher, same gating as TestLiveCRUD. A wallet connection additionally needs a
// verifier access key already imported into the realm (docs/eudi-wallet.md §2.4 step 1,
// `POST /admin/realms/{realm}/verifier-keys`) — generating and importing a valid, non-self-signed EC
// certificate chain is out of scope for this test, so it is separately gated on
// HELIX_LIVE_WALLET_ACCESS_KEY_REF (e.g. "software:gov/primary") and HELIX_LIVE_WALLET_TRUST_ANCHORS (a
// PEM bundle of acceptable PID-issuer CA certificates). Run it with:
//
//	HELIX_LIVE_BASEURL=http://localhost:8083 \
//	HELIX_LIVE_WALLET_ACCESS_KEY_REF=software:gov/primary \
//	HELIX_LIVE_WALLET_TRUST_ANCHORS="$(cat ca.pem)" \
//	go test ./internal/provider -run TestLiveWalletIdentityProviderCRUD -v
func TestLiveWalletIdentityProviderCRUD(t *testing.T) {
	base := os.Getenv("HELIX_LIVE_BASEURL")
	accessKeyRef := os.Getenv("HELIX_LIVE_WALLET_ACCESS_KEY_REF")
	trustAnchors := os.Getenv("HELIX_LIVE_WALLET_TRUST_ANCHORS")
	if base == "" || accessKeyRef == "" || trustAnchors == "" {
		t.Skip("set HELIX_LIVE_BASEURL, HELIX_LIVE_WALLET_ACCESS_KEY_REF and HELIX_LIVE_WALLET_TRUST_ANCHORS " +
			"to run the live wallet identity-provider CRUD test")
	}
	realm := getenv("HELIX_REALM", "master")
	c := NewClient(base, base+"/realms/"+realm, realm, os.Getenv("HELIX_CLIENT_ID"), os.Getenv("HELIX_CLIENT_SECRET"))
	ctx := context.Background()

	const alias = "tf-live-wallet"
	_ = c.DeleteIdentityProvider(ctx, alias) // best-effort pre-clean

	write := IdentityProviderWrite{
		Alias: alias, Protocol: "eudi-wallet", DisplayName: "TF Live Wallet", Enabled: true,
		Config: map[string]string{
			"accessKeyRef":      accessKeyRef,
			"trustAnchors":      trustAnchors,
			"credentialFormats": `["dc+sd-jwt","mso_mdoc"]`,
		},
	}
	if err := c.CreateIdentityProvider(ctx, write); err != nil {
		t.Fatalf("create wallet idp: %v", err)
	}
	ip, nf, err := c.GetIdentityProvider(ctx, alias)
	if err != nil || nf {
		t.Fatalf("get wallet idp: err=%v nf=%v", err, nf)
	}
	if ip.Protocol != "eudi-wallet" || ip.ConfigString("accessKeyRef") != accessKeyRef {
		t.Fatalf("unexpected wallet idp after create: %+v", ip)
	}
	if _, present := ip.Config["accessCertificatePrivateKey"]; present {
		t.Fatalf("a secret key must never come back from the admin API")
	}

	write.DisplayName = "TF Live Wallet v2"
	if err := c.UpdateIdentityProvider(ctx, alias, write); err != nil {
		t.Fatalf("update wallet idp: %v", err)
	}
	ip, _, _ = c.GetIdentityProvider(ctx, alias)
	if ip.DisplayName != "TF Live Wallet v2" {
		t.Fatalf("expected updated displayName, got %q", ip.DisplayName)
	}

	if err := c.DeleteIdentityProvider(ctx, alias); err != nil {
		t.Fatalf("delete wallet idp: %v", err)
	}
	if _, nf, _ := c.GetIdentityProvider(ctx, alias); !nf {
		t.Fatalf("expected wallet idp gone after delete")
	}
	t.Logf("live wallet identity-provider CRUD OK against %s", base)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
