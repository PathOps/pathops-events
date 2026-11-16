package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	// keysMaxAge bounds how long fetched keys are used without a refresh, so a
	// key Dex has withdrawn stops verifying. Past it, keys that cannot be
	// refreshed are not used (fail closed).
	keysMaxAge = 10 * time.Minute
	// refreshInterval is the minimum time between two fetches: a token with an
	// unknown kid triggers at most one refresh per interval, never a loop.
	refreshInterval = 30 * time.Second
	// fetchTimeout bounds one discovery + JWKS fetch.
	fetchTimeout = 10 * time.Second
	// maxDocument bounds a discovery or JWKS document.
	maxDocument = 1 << 20
)

// keySet holds the issuer's signing keys, found through OIDC discovery
// (<issuer>/.well-known/openid-configuration -> jwks_uri) and cached.
type keySet struct {
	issuer string
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex
	keys      jose.JSONWebKeySet
	fetched   time.Time // last successful fetch
	attempted time.Time // last fetch attempt
	fetches   int       // successful and failed fetches (tests)
}

func newKeySet(issuer string, client *http.Client, now func() time.Time) *keySet {
	return &keySet{issuer: issuer, client: client, now: now}
}

// key returns the verification key for kid. Known kid: the cache. Unknown
// kid: one refresh (if none happened within refreshInterval), then the cache
// again. Expired cache: a refresh is required; if it fails, ErrUnavailable.
func (k *keySet) key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if k.fetched.IsZero() || now.Sub(k.fetched) > keysMaxAge {
		if err := k.refresh(ctx, now); err != nil && (k.fetched.IsZero() || now.Sub(k.fetched) > keysMaxAge) {
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	if found := k.keys.Key(kid); len(found) == 1 {
		return &found[0], nil
	}
	if now.Sub(k.attempted) >= refreshInterval {
		if err := k.refresh(ctx, now); err != nil {
			return nil, fmt.Errorf("%w: kid %q unknown and the keys cannot be refreshed: %v", ErrUnknownKey, kid, err)
		}
		if found := k.keys.Key(kid); len(found) == 1 {
			return &found[0], nil
		}
	}
	return nil, fmt.Errorf("%w: kid %q", ErrUnknownKey, kid)
}

// refresh fetches the discovery document and the JWKS it names. Called with
// k.mu held; rate limited by the callers through k.attempted.
func (k *keySet) refresh(ctx context.Context, now time.Time) error {
	if !k.attempted.IsZero() && now.Sub(k.attempted) < refreshInterval {
		return errors.New("refreshed less than 30s ago")
	}
	k.attempted = now
	k.fetches++
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	var disc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := k.get(ctx, k.issuer+"/.well-known/openid-configuration", &disc); err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	if disc.Issuer != k.issuer {
		return fmt.Errorf("discovery names issuer %q, not %q", disc.Issuer, k.issuer)
	}
	iss, _ := url.Parse(k.issuer)
	jwks, err := url.Parse(disc.JWKSURI)
	if err != nil || jwks.Scheme != "https" || jwks.Host != iss.Host {
		return fmt.Errorf("jwks_uri %q is not an https URL on the issuer's host", disc.JWKSURI)
	}
	var set jose.JSONWebKeySet
	if err := k.get(ctx, disc.JWKSURI, &set); err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	k.keys, k.fetched = set, now
	return nil
}

func (k *keySet) get(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := k.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxDocument)).Decode(v)
}
