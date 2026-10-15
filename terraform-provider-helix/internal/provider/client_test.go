/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A fake Helix admin API: a token endpoint + the realm-scoped application/role endpoints.
func fakeServer(t *testing.T, tokenCalls *int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/master/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		*tokenCalls++
		if u, p, ok := r.BasicAuth(); !ok || u != "admin-cli" || p != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "AT", "token_type": "Bearer", "expires_in": 300})
	})
	mux.HandleFunc("/admin/realms/master/applications", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer AT" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/admin/realms/master/applications/billing", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Application{Name: "billing", DisplayName: "Billing", Enabled: true})
	})
	mux.HandleFunc("/admin/realms/master/roles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(Role{RoleID: "r-123", Name: "viewer"})
			return
		}
		_ = json.NewEncoder(w).Encode([]Role{{RoleID: "r-123", Name: "viewer"}})
	})
	return httptest.NewServer(mux)
}

func TestClientCachesTokenAcrossRequests(t *testing.T) {
	var tokenCalls int
	srv := fakeServer(t, &tokenCalls)
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL+"/realms/master", "master", "admin-cli", "s3cret")
	ctx := context.Background()

	if err := c.CreateApplication(ctx, Application{Name: "x", Enabled: true}); err != nil {
		t.Fatalf("create app: %v", err)
	}
	if _, _, err := c.GetApplication(ctx, "billing"); err != nil {
		t.Fatalf("get app: %v", err)
	}
	if tokenCalls != 1 {
		t.Fatalf("expected 1 token fetch (cached), got %d", tokenCalls)
	}
}

func TestClientRefreshesExpiredToken(t *testing.T) {
	var tokenCalls int
	srv := fakeServer(t, &tokenCalls)
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL+"/realms/master", "master", "admin-cli", "s3cret")
	now := time.Unix(1_000_000, 0)
	c.now = func() time.Time { return now }
	ctx := context.Background()

	_, _, _ = c.GetApplication(ctx, "billing") // token fetched, expires at now+300s (skew 30s → reuse <270s)
	now = now.Add(200 * time.Second)           // within expiry-minus-skew window → reuse
	_, _, _ = c.GetApplication(ctx, "billing")
	if tokenCalls != 1 {
		t.Fatalf("expected 1 token fetch within window, got %d", tokenCalls)
	}
	now = now.Add(100 * time.Second) // total +300s → past expiry-minus-skew → refresh
	_, _, _ = c.GetApplication(ctx, "billing")
	if tokenCalls != 2 {
		t.Fatalf("expected token refresh after expiry, got %d", tokenCalls)
	}
}

func TestCreateRoleReturnsServerID(t *testing.T) {
	var tokenCalls int
	srv := fakeServer(t, &tokenCalls)
	defer srv.Close()

	c := NewClient(srv.URL, srv.URL+"/realms/master", "master", "admin-cli", "s3cret")
	created, err := c.CreateRole(context.Background(), Role{Name: "viewer"})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if created.RoleID != "r-123" {
		t.Fatalf("expected role id r-123, got %q", created.RoleID)
	}
}

// TestDo_DecodesFieldErrors: a 400 response carrying {message, fieldErrors} (AdminValidationAdvice's
// shape) must come back as an *AdminError with every field error, not just the top-level message, so a
// resource can turn each one into its own Terraform diagnostic.
func TestDo_DecodesFieldErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "Wallet provider 'w' is invalid",
			"fieldErrors": map[string]string{
				"alias":               "alias is required",
				"config.accessKeyRef": "accessKeyRef is required (a signing key imported into this realm)",
				"config.minimumLoa":   "minimumLoa must be an eIDAS level of assurance",
			},
		})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, srv.URL+"/realms/master", "master", "", "")

	err := c.CreateApplication(context.Background(), Application{Name: "x", Enabled: true})
	if err == nil {
		t.Fatalf("expected an error")
	}
	var ae *AdminError
	if !errors.As(err, &ae) {
		t.Fatalf("expected an *AdminError, got %T: %v", err, err)
	}
	if ae.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", ae.StatusCode)
	}
	if ae.Message != "Wallet provider 'w' is invalid" {
		t.Fatalf("expected the top-level message to be kept, got %q", ae.Message)
	}
	if len(ae.FieldErrors) != 3 {
		t.Fatalf("expected 3 field errors, got %d: %v", len(ae.FieldErrors), ae.FieldErrors)
	}
	for field, want := range map[string]string{
		"alias":               "alias is required",
		"config.accessKeyRef": "accessKeyRef is required (a signing key imported into this realm)",
		"config.minimumLoa":   "minimumLoa must be an eIDAS level of assurance",
	} {
		if got := ae.FieldErrors[field]; got != want {
			t.Fatalf("field %q: expected %q, got %q", field, want, got)
		}
	}
	// err.Error() must still be a useful plain string for callers that don't unwrap it.
	if !strings.Contains(err.Error(), "alias is required") {
		t.Fatalf("expected Error() to mention a field error, got %q", err.Error())
	}
}

// TestDo_PlainMessageWithoutFieldErrors: a 400 with only {message} must still work as before (no panic,
// no spurious empty FieldErrors map reported).
func TestDo_PlainMessageWithoutFieldErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "alias already in use"})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, srv.URL+"/realms/master", "master", "", "")

	err := c.CreateApplication(context.Background(), Application{Name: "x", Enabled: true})
	var ae *AdminError
	if !errors.As(err, &ae) {
		t.Fatalf("expected an *AdminError, got %T: %v", err, err)
	}
	if ae.Message != "alias already in use" {
		t.Fatalf("unexpected message: %q", ae.Message)
	}
	if len(ae.FieldErrors) != 0 {
		t.Fatalf("expected no field errors, got %v", ae.FieldErrors)
	}
}

func TestAnonymousModeSendsNoBearer(t *testing.T) {
	gotAuth := "unset"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode([]Role{})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, srv.URL+"/realms/master", "master", "", "") // no client id → anonymous
	if _, _, err := c.GetRoleByName(context.Background(), "none"); err != nil {
		t.Fatalf("anon get: %v", err)
	}
	if gotAuth != "" {
		t.Fatalf("expected no Authorization header in anonymous mode, got %q", gotAuth)
	}
}
