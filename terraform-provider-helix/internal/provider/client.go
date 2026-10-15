/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// Package provider implements the Helix IAM Terraform provider (IAM-as-code). This file is the admin
// API client: it authenticates with the OAuth2 client-credentials grant (token cached until expiry)
// and exposes typed CRUD for the realm-scoped admin resources the provider manages.
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client talks to the Helix IAM admin API for one realm.
type Client struct {
	httpClient   *http.Client
	baseURL      string // admin API origin, e.g. https://idp.example.com
	issuer       string // realm issuer that mints the admin token, e.g. https://idp.example.com/realms/master
	realm        string // the realm being administered
	clientID     string
	clientSecret string

	mu          sync.Mutex
	cachedToken string
	expires     time.Time
	now         func() time.Time
}

// NewClient builds a client. When clientID is empty the client operates anonymously (no bearer token) —
// useful only against a dev instance with admin auth disabled; production always uses client-credentials.
func NewClient(baseURL, issuer, realm, clientID, clientSecret string) *Client {
	return &Client{
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		baseURL:      strings.TrimRight(baseURL, "/"),
		issuer:       strings.TrimRight(issuer, "/"),
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
		now:          time.Now,
	}
}

func (c *Client) realmRoot() string {
	return fmt.Sprintf("%s/admin/realms/%s", c.baseURL, url.PathEscape(c.realm))
}

// token returns a valid bearer token (cached), fetching one via client_credentials when needed.
func (c *Client) token(ctx context.Context) (string, error) {
	if c.clientID == "" {
		return "", nil // anonymous mode
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedToken != "" && c.now().Before(c.expires.Add(-30*time.Second)) {
		return c.cachedToken, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.issuer+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed: %d %s", resp.StatusCode, string(body))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", err
	}
	c.cachedToken = tok.AccessToken
	ttl := tok.ExpiresIn
	if ttl == 0 {
		ttl = 300
	}
	c.expires = c.now().Add(time.Duration(ttl) * time.Second)
	return c.cachedToken, nil
}

// do issues an authenticated request to a realm-scoped admin path (e.g. "/applications"). out may be nil.
// A 404 is reported via the returned notFound bool so resources can drop themselves from state.
func (c *Client) do(ctx context.Context, method, path string, in, out any) (notFound bool, err error) {
	var body io.Reader
	if in != nil {
		b, mErr := json.Marshal(in)
		if mErr != nil {
			return false, mErr
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.realmRoot()+path, body)
	if err != nil {
		return false, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	tok, err := c.token(ctx)
	if err != nil {
		return false, err
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return true, nil
	}
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		msg := strings.TrimSpace(string(b))
		// Surface the admin API's {message} when present.
		var e struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(b, &e) == nil && e.Message != "" {
			msg = e.Message
		}
		return false, fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, msg)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return false, json.NewDecoder(resp.Body).Decode(out)
	}
	return false, nil
}

// --- Application ---

type Application struct {
	RealmID       string `json:"realmId,omitempty"`
	Name          string `json:"name"`
	DisplayName   string `json:"displayName,omitempty"`
	Description   string `json:"description,omitempty"`
	SubjectClaim  string `json:"subjectClaim,omitempty"`
	AuthFlowAlias string `json:"authFlowAlias,omitempty"`
	Enabled       bool   `json:"enabled"`
}

func (c *Client) CreateApplication(ctx context.Context, app Application) error {
	_, err := c.do(ctx, http.MethodPost, "/applications", app, nil)
	return err
}

func (c *Client) GetApplication(ctx context.Context, name string) (*Application, bool, error) {
	var app Application
	nf, err := c.do(ctx, http.MethodGet, "/applications/"+url.PathEscape(name), nil, &app)
	if err != nil || nf {
		return nil, nf, err
	}
	return &app, false, nil
}

func (c *Client) UpdateApplication(ctx context.Context, app Application) error {
	_, err := c.do(ctx, http.MethodPut, "/applications/"+url.PathEscape(app.Name), app, nil)
	return err
}

func (c *Client) DeleteApplication(ctx context.Context, name string) error {
	_, err := c.do(ctx, http.MethodDelete, "/applications/"+url.PathEscape(name), nil, nil)
	return err
}

// --- Realm role ---

type Role struct {
	RealmID     string `json:"realmId,omitempty"`
	RoleID      string `json:"roleId,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (c *Client) CreateRole(ctx context.Context, role Role) (*Role, error) {
	var created Role
	_, err := c.do(ctx, http.MethodPost, "/roles", role, &created)
	return &created, err
}

// GetRoleByName finds a realm role by name (the roles endpoint lists; there is no get-by-id).
func (c *Client) GetRoleByName(ctx context.Context, name string) (*Role, bool, error) {
	var roles []Role
	if _, err := c.do(ctx, http.MethodGet, "/roles", nil, &roles); err != nil {
		return nil, false, err
	}
	for i := range roles {
		if roles[i].Name == name {
			return &roles[i], false, nil
		}
	}
	return nil, true, nil
}

func (c *Client) DeleteRole(ctx context.Context, roleID string) error {
	_, err := c.do(ctx, http.MethodDelete, "/roles/"+url.PathEscape(roleID), nil, nil)
	return err
}

// --- Identity provider connection ---
//
// The admin API models every federation connection (OIDC/SAML/eID/LDAP/EUDI wallet) as one resource:
// an alias, a protocol, a display name, an enabled flag and a flat string "config" map whose keys are
// protocol-specific (dotted for nested settings, e.g. "pid.requestedClaims"). A write (create/update)
// sends config as a Map<String,String>; a read returns it as Map<String,Object> because secret config
// keys come back as "<key>Set": true|false booleans instead of their value (never the value itself —
// see IdentityProviderAdminView on the server). IdentityProviderWrite/IdentityProviderRead reflect that
// asymmetry.

// IdentityProviderWrite is the body of a create or update.
type IdentityProviderWrite struct {
	Alias       string            `json:"alias"`
	Protocol    string            `json:"protocol"`
	DisplayName string            `json:"displayName,omitempty"`
	Enabled     bool              `json:"enabled"`
	Config      map[string]string `json:"config,omitempty"`
}

// IdentityProviderRead is an identity-provider connection as GET returns it: secrets are represented by
// "<key>Set" booleans in Config, never by their value.
type IdentityProviderRead struct {
	RealmID     string         `json:"realmId,omitempty"`
	Alias       string         `json:"alias"`
	Protocol    string         `json:"protocol"`
	DisplayName string         `json:"displayName,omitempty"`
	Enabled     bool           `json:"enabled"`
	Config      map[string]any `json:"config,omitempty"`
}

// ConfigString reads a plain (non-secret) string config value; "" when absent. Secret keys never appear
// here under their own name (only as the "<key>Set" boolean), so this is never used for a secret.
func (ip *IdentityProviderRead) ConfigString(key string) string {
	if ip.Config == nil {
		return ""
	}
	if s, ok := ip.Config[key].(string); ok {
		return s
	}
	return ""
}

func (c *Client) CreateIdentityProvider(ctx context.Context, ip IdentityProviderWrite) error {
	_, err := c.do(ctx, http.MethodPost, "/identity-providers", ip, nil)
	return err
}

func (c *Client) GetIdentityProvider(ctx context.Context, alias string) (*IdentityProviderRead, bool, error) {
	var ip IdentityProviderRead
	nf, err := c.do(ctx, http.MethodGet, "/identity-providers/"+url.PathEscape(alias), nil, &ip)
	if err != nil || nf {
		return nil, nf, err
	}
	return &ip, false, nil
}

func (c *Client) UpdateIdentityProvider(ctx context.Context, alias string, ip IdentityProviderWrite) error {
	_, err := c.do(ctx, http.MethodPut, "/identity-providers/"+url.PathEscape(alias), ip, nil)
	return err
}

func (c *Client) DeleteIdentityProvider(ctx context.Context, alias string) error {
	_, err := c.do(ctx, http.MethodDelete, "/identity-providers/"+url.PathEscape(alias), nil, nil)
	return err
}
