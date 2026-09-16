package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
