// Package oidctest is a test OIDC issuer shaped like the Cell's Dex: an
// HTTPS server with OIDC discovery (/.well-known/openid-configuration) whose
// jwks_uri (/keys) publishes RSA signing keys, and a minter of RS256 tokens
// with Dex's claims. Keys can be rotated and fetches are counted. Tests only.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Issuer is a running test issuer.
type Issuer struct {
	URL    string // the issuer, https://127.0.0.1:<port>
	Server *httptest.Server

	mu        sync.Mutex
	keys      []Key // published, newest first
	discovery int
	jwks      int
	down      bool
	announced string // the issuer the discovery document names ("": URL)
}

// Key is a signing key and its kid.
type Key struct {
	ID      string
	Private *rsa.PrivateKey
}

// NewKey returns a fresh 2048-bit RSA key named kid.
func NewKey(t testing.TB, kid string) Key {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return Key{ID: kid, Private: k}
}

// New starts an issuer publishing one key, "k1".
func New(t testing.TB) *Issuer {
	t.Helper()
	is := &Issuer{keys: []Key{NewKey(t, "k1")}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		is.mu.Lock()
		is.discovery++
		down, announced := is.down, is.announced
		is.mu.Unlock()
		if down {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if announced == "" {
			announced = is.URL
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": announced, "jwks_uri": is.URL + "/keys", "authorization_endpoint": is.URL + "/auth",
			"token_endpoint": is.URL + "/token", "id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported": []string{"S256", "plain"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		is.mu.Lock()
		is.jwks++
		var set jose.JSONWebKeySet
		for _, k := range is.keys {
			set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.Private.PublicKey, KeyID: k.ID, Algorithm: "RS256", Use: "sig"})
		}
		down := is.down
		is.mu.Unlock()
		if down {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	is.Server = httptest.NewTLSServer(mux)
	is.URL = is.Server.URL
	t.Cleanup(is.Server.Close)
	return is
}

// Roots trusts the issuer's TLS certificate (as the Cell CA does for Dex).
func (is *Issuer) Roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(is.Server.Certificate())
	return p
}

// Client is an HTTPS client trusting only the issuer's certificate.
func (is *Issuer) Client() *http.Client { return is.Server.Client() }

// Key returns the newest published key.
func (is *Issuer) Key() Key {
	is.mu.Lock()
	defer is.mu.Unlock()
	return is.keys[0]
}

// Rotate publishes k as the newest key; keep the previous ones published
// when keep is true (Dex keeps verification keys until their tokens expire).
func (is *Issuer) Rotate(k Key, keep bool) {
	is.mu.Lock()
	defer is.mu.Unlock()
	if keep {
		is.keys = append([]Key{k}, is.keys...)
	} else {
		is.keys = []Key{k}
	}
}

// SetDown makes discovery and JWKS answer 503 (Dex unavailable).
func (is *Issuer) SetDown(down bool) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.down = down
}

// Announce makes the discovery document name issuer instead of URL.
func (is *Issuer) Announce(issuer string) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.announced = issuer
}

// Fetches returns how many discovery and JWKS documents were served.
func (is *Issuer) Fetches() (discovery, jwks int) {
	is.mu.Lock()
	defer is.mu.Unlock()
	return is.discovery, is.jwks
}

// Claims are a Dex access token's claims; zero fields are left out.
type Claims struct {
	Issuer    string
	Subject   string
	Audience  []string
	Expiry    time.Time
	NotBefore time.Time
	IssuedAt  time.Time
	Email     string
	Name      string
}

// Claims returns valid claims for subject at this issuer, issued at now for
// audience, expiring in 5 minutes (Dex's lifetime).
func (is *Issuer) Claims(now time.Time, audience, subject string) Claims {
	return Claims{Issuer: is.URL, Subject: subject, Audience: []string{audience}, IssuedAt: now,
		Expiry: now.Add(5 * time.Minute), Email: subject + "@example.test", Name: "User " + subject}
}

// Mint signs c with k (RS256, kid k.ID).
func Mint(t testing.TB, k Key, c Claims) string {
	t.Helper()
	return MintWith(t, jose.SigningKey{Algorithm: jose.RS256, Key: k.Private}, k.ID, c)
}

// MintWith signs c with any go-jose signing key and kid.
func MintWith(t testing.TB, key jose.SigningKey, kid string, c Claims) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader(jose.HeaderKey("kid"), kid)
	}
	s, err := jose.NewSigner(key, opts)
	if err != nil {
		t.Fatal(err)
	}
	reg := jwt.Claims{Issuer: c.Issuer, Subject: c.Subject, Audience: c.Audience}
	for _, tm := range []struct {
		v   time.Time
		set **jwt.NumericDate
	}{{c.Expiry, &reg.Expiry}, {c.NotBefore, &reg.NotBefore}, {c.IssuedAt, &reg.IssuedAt}} {
		if !tm.v.IsZero() {
			*tm.set = jwt.NewNumericDate(tm.v)
		}
	}
	extra := map[string]any{}
	if c.Email != "" {
		extra["email"], extra["email_verified"] = c.Email, true
	}
	if c.Name != "" {
		extra["name"] = c.Name
	}
	raw, err := jwt.Signed(s).Claims(reg).Claims(extra).Serialize()
	if err != nil {
		t.Fatal(fmt.Errorf("mint: %w", err))
	}
	return raw
}

// MintTyped signs claims as they are with k (RS256, kid k.ID) and the JWS
// "typ" typ: Dex's Operation Authorization Tokens and other typed tokens.
func MintTyped(t testing.TB, k Key, typ string, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader(jose.HeaderKey("kid"), k.ID)
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k.Private}, opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(s).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(fmt.Errorf("mint: %w", err))
	}
	return raw
}
