package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/PathOps/pathops-events/internal/oidctest"
)

// aud is the PathOps UI's client: the human token's audience.
const aud = "pathops-ui"

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func setup(t *testing.T) (*oidctest.Issuer, *Verifier, *clock) {
	t.Helper()
	is := oidctest.New(t)
	clk := &clock{t: time.Now()}
	return is, newVerifier(is.URL, aud, is.Client(), clk.now), clk
}

func expectErr(t *testing.T, v *Verifier, raw string, want error) {
	t.Helper()
	id, err := v.Verify(context.Background(), raw)
	if !errors.Is(err, want) {
		t.Fatalf("Verify = %+v, %v; want %v", id, err, want)
	}
}

func TestValidToken(t *testing.T) {
	is, v, clk := setup(t)
	id, err := v.Verify(context.Background(), oidctest.Mint(t, is.Key(), is.Claims(clk.now(), aud, "alice")))
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "alice" || id.Issuer != is.URL || !id.Expiry.After(clk.now()) {
		t.Fatalf("Identity = %+v", id)
	}
}

func TestAudienceListContainingOurs(t *testing.T) {
	is, v, clk := setup(t)
	c := is.Claims(clk.now(), aud, "alice")
	c.Audience = []string{"other", aud}
	if _, err := v.Verify(context.Background(), oidctest.Mint(t, is.Key(), c)); err != nil {
		t.Fatal(err)
	}
}

func TestRejectedClaims(t *testing.T) {
	is, v, clk := setup(t)
	now := clk.now()
	for name, tc := range map[string]struct {
		edit func(*oidctest.Claims)
		want error
	}{
		"wrong issuer, valid signature": {func(c *oidctest.Claims) { c.Issuer = "https://dex-globex.demo.pathops.io" }, ErrIssuer},
		"issuer with a trailing slash":  {func(c *oidctest.Claims) { c.Issuer += "/" }, ErrIssuer},
		"wrong audience":                {func(c *oidctest.Claims) { c.Audience = []string{"zot"} }, ErrAudience},
		"expired":                       {func(c *oidctest.Claims) { c.IssuedAt, c.Expiry = now.Add(-10*time.Minute), now.Add(-31*time.Second) }, ErrExpired},
		"nbf in the future":             {func(c *oidctest.Claims) { c.NotBefore = now.Add(31 * time.Second) }, ErrNotYetValid},
		"iat in the future":             {func(c *oidctest.Claims) { c.IssuedAt = now.Add(31 * time.Second) }, ErrIssuedInFuture},
		"no subject":                    {func(c *oidctest.Claims) { c.Subject = "" }, ErrClaims},
		"no audience":                   {func(c *oidctest.Claims) { c.Audience = nil }, ErrClaims},
		"no expiry":                     {func(c *oidctest.Claims) { c.Expiry = time.Time{} }, ErrClaims},
		"no issued-at":                  {func(c *oidctest.Claims) { c.IssuedAt = time.Time{} }, ErrClaims},
		"no issuer":                     {func(c *oidctest.Claims) { c.Issuer = "" }, ErrClaims},
	} {
		t.Run(name, func(t *testing.T) {
			c := is.Claims(now, aud, "alice")
			tc.edit(&c)
			expectErr(t, v, oidctest.Mint(t, is.Key(), c), tc.want)
		})
	}
}

// The skew is 30 s: within it exp, nbf and iat still pass.
func TestLeeway(t *testing.T) {
	is, v, clk := setup(t)
	now := clk.now()
	c := is.Claims(now, aud, "alice")
	c.IssuedAt, c.Expiry, c.NotBefore = now.Add(25*time.Second), now.Add(-25*time.Second), now.Add(25*time.Second)
	if _, err := v.Verify(context.Background(), oidctest.Mint(t, is.Key(), c)); err != nil {
		t.Fatalf("within the %s leeway: %v", Leeway, err)
	}
}

func TestAttackerKey(t *testing.T) {
	is, v, clk := setup(t)
	evil := oidctest.NewKey(t, is.Key().ID) // same kid, same iss string, other key
	expectErr(t, v, oidctest.Mint(t, evil, is.Claims(clk.now(), aud, "alice")), ErrSignature)
	evil.ID = "evil"
	expectErr(t, v, oidctest.Mint(t, evil, is.Claims(clk.now(), aud, "alice")), ErrUnknownKey)
}

func TestAlgorithms(t *testing.T) {
	is, v, clk := setup(t)
	c := is.Claims(clk.now(), aud, "alice")
	body := oidctest.Mint(t, is.Key(), c)
	payload := strings.Split(body, ".")[1]
	enc := func(h string) string { return base64.RawURLEncoding.EncodeToString([]byte(h)) }

	// alg=none, unsigned (empty and garbage signature).
	none := enc(`{"alg":"none","typ":"JWT","kid":"k1"}`) + "." + payload
	expectErr(t, v, none+".", ErrMalformed)
	expectErr(t, v, none+"."+enc("x"), ErrMalformed)
	// HS256 keyed with the issuer's public key (algorithm confusion).
	pub, _ := x509.MarshalPKIXPublicKey(&is.Key().Private.PublicKey)
	expectErr(t, v, oidctest.MintWith(t, jose.SigningKey{Algorithm: jose.HS256, Key: pub}, "k1", c), ErrAlgorithm)
	// ES256 by an attacker: an algorithm the Cell's Dex never uses.
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	expectErr(t, v, oidctest.MintWith(t, jose.SigningKey{Algorithm: jose.ES256, Key: ec}, "k1", c), ErrAlgorithm)
	// RS512 with the issuer's own key: still not an accepted algorithm.
	expectErr(t, v, oidctest.MintWith(t, jose.SigningKey{Algorithm: jose.RS512, Key: is.Key().Private}, "k1", c), ErrAlgorithm)
}

func TestMalformed(t *testing.T) {
	is, v, clk := setup(t)
	good := oidctest.Mint(t, is.Key(), is.Claims(clk.now(), aud, "alice"))
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"mallory","iss":"`+is.URL+`"}`)) + "." + parts[2]
	expectErr(t, v, tampered, ErrSignature)
	for _, raw := range []string{"", "x", "a.b", "a.b.c", strings.Repeat("a", MaxLength+1), good + "x"} {
		if _, err := v.Verify(context.Background(), raw); err == nil {
			t.Fatalf("%q accepted", raw)
		}
	}
	expectErr(t, v, oidctest.MintWith(t, jose.SigningKey{Algorithm: jose.RS256, Key: is.Key().Private}, "", is.Claims(clk.now(), aud, "alice")), ErrMalformed)
}

func TestKeysAreCached(t *testing.T) {
	is, v, clk := setup(t)
	for range 20 {
		if _, err := v.Verify(context.Background(), oidctest.Mint(t, is.Key(), is.Claims(clk.now(), aud, "alice"))); err != nil {
			t.Fatal(err)
		}
	}
	if d, j := is.Fetches(); d != 1 || j != 1 {
		t.Fatalf("fetches discovery=%d jwks=%d, want 1 and 1", d, j)
	}
}

func TestRotationRefreshesOnceForUnknownKid(t *testing.T) {
	is, v, clk := setup(t)
	old := is.Key()
	if _, err := v.Verify(context.Background(), oidctest.Mint(t, old, is.Claims(clk.now(), aud, "alice"))); err != nil {
		t.Fatal(err)
	}
	clk.add(refreshInterval)
	is.Rotate(oidctest.NewKey(t, "k2"), true)
	if _, err := v.Verify(context.Background(), oidctest.Mint(t, is.Key(), is.Claims(clk.now(), aud, "alice"))); err != nil {
		t.Fatalf("token of the rotated key: %v", err)
	}
	if _, err := v.Verify(context.Background(), oidctest.Mint(t, old, is.Claims(clk.now(), aud, "alice"))); err != nil {
		t.Fatalf("token of the previous, still published key: %v", err)
	}
	if _, j := is.Fetches(); j != 2 {
		t.Fatalf("jwks fetches = %d, want 2 (one refresh for the new kid)", j)
	}
	// Unknown kids within the interval: no further fetch (no refresh loop).
	evil := oidctest.NewKey(t, "unknown")
	for range 10 {
		expectErr(t, v, oidctest.Mint(t, evil, is.Claims(clk.now(), aud, "alice")), ErrUnknownKey)
	}
	if _, j := is.Fetches(); j != 2 {
		t.Fatalf("jwks fetches = %d after unknown kids, want still 2", j)
	}
	clk.add(refreshInterval)
	expectErr(t, v, oidctest.Mint(t, evil, is.Claims(clk.now(), aud, "alice")), ErrUnknownKey)
	if _, j := is.Fetches(); j != 3 {
		t.Fatalf("jwks fetches = %d, want 3 (one refresh per interval)", j)
	}
}

func TestWithdrawnKeyStopsVerifyingAfterMaxAge(t *testing.T) {
	is, v, clk := setup(t)
	old := is.Key()
	if _, err := v.Verify(context.Background(), oidctest.Mint(t, old, is.Claims(clk.now(), aud, "alice"))); err != nil {
		t.Fatal(err)
	}
	is.Rotate(oidctest.NewKey(t, "k2"), false)
	clk.add(keysMaxAge + time.Second)
	expectErr(t, v, oidctest.Mint(t, old, is.Claims(clk.now(), aud, "alice")), ErrUnknownKey)
}

func TestIssuerUnavailableFailsClosed(t *testing.T) {
	is, v, clk := setup(t)
	is.SetDown(true)
	expectErr(t, v, oidctest.Mint(t, is.Key(), is.Claims(clk.now(), aud, "alice")), ErrUnavailable)

	is.SetDown(false)
	clk.add(refreshInterval)
	if _, err := v.Verify(context.Background(), oidctest.Mint(t, is.Key(), is.Claims(clk.now(), aud, "alice"))); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	// Cached keys keep working while fresh; past the max age a refresh is required.
	is.SetDown(true)
	clk.add(keysMaxAge / 2)
	if _, err := v.Verify(context.Background(), oidctest.Mint(t, is.Key(), is.Claims(clk.now(), aud, "alice"))); err != nil {
		t.Fatalf("fresh cache while the issuer is down: %v", err)
	}
	clk.add(keysMaxAge)
	expectErr(t, v, oidctest.Mint(t, is.Key(), is.Claims(clk.now(), aud, "alice")), ErrUnavailable)
}

// A discovery document that names another issuer is not used.
func TestDiscoveryMustNameTheIssuer(t *testing.T) {
	is, v, clk := setup(t)
	is.Announce("https://dex-globex.demo.pathops.io")
	expectErr(t, v, oidctest.Mint(t, is.Key(), is.Claims(clk.now(), aud, "alice")), ErrUnavailable)
}

func TestTLSIsVerified(t *testing.T) {
	is := oidctest.New(t)
	clk := &clock{t: time.Now()}
	v := NewVerifier(is.URL, aud, nil) // system roots: the test certificate is not trusted
	expectErr(t, v, oidctest.Mint(t, is.Key(), is.Claims(clk.now(), aud, "alice")), ErrUnavailable)
	if _, err := NewVerifier(is.URL, aud, is.Roots()).Verify(context.Background(), oidctest.Mint(t, is.Key(), is.Claims(time.Now(), aud, "alice"))); err != nil {
		t.Fatalf("with the issuer's CA: %v", err)
	}
}

// An Operation Authorization Token never authenticates a person, even one
// whose claims would pass as an access token's.
func TestOperationAuthorizationIsNotIdentity(t *testing.T) {
	is, v, clk := setup(t)
	now := clk.now()
	oat := oidctest.MintTyped(t, is.Key(), OperationAuthorizationType, map[string]any{"iss": is.URL, "sub": "alice", "aud": aud,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "pathops_plan": "plan-1"})
	expectErr(t, v, oat, ErrMalformed)
}

// The CLI's token (its own client) is a valid Dex token of this Cell, but not
// the PathOps UI's: refused.
func TestOtherClientOfTheSameDex(t *testing.T) {
	is, v, clk := setup(t)
	for _, other := range []string{"pathops-cli", "forgejo", "pathops-artifact-store-web", "pathops-events-web", "pathops-events"} {
		expectErr(t, v, oidctest.Mint(t, is.Key(), is.Claims(clk.now(), other, "alice")), ErrAudience)
	}
}
