// Package workload authenticates the publishers of invalidations: the
// Tenant Control Plane's Kubernetes ServiceAccount, with a short-lived token
// of pathops-events' audience (a projected token: the kubelet obtains it
// from the TokenRequest API and rotates it). Dex is not involved (Decision
// 0063).
//
// The API server reviews the token (TokenReview, with the audience): its
// signature, expiry, audience and, for a Pod-bound token, that the Pod still
// exists. pathops-events then requires, beside the review:
//
//   - the reviewed username to be exactly the expected ServiceAccount;
//   - the reviewed audiences to include the audience;
//   - the token's own claims (read after the review): the cluster's
//     ServiceAccount issuer, exactly one audience (pathops-events), a
//     lifetime of at most MaxTTL and not expired.
//
// A person's OIDC token (another issuer), a token of another ServiceAccount,
// of another or an additional audience, or a long-lived one is refused.
package workload

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// MaxTokenLength bounds a presented token.
const MaxTokenLength = 8192

var (
	// ErrUnauthenticated: not a valid token of the expected publisher.
	ErrUnauthenticated = errors.New("unauthenticated")
	// ErrUnavailable: the API server could not be asked.
	ErrUnavailable = errors.New("token review unavailable")
)

// Verifier authenticates a publisher's bearer token.
type Verifier struct {
	APIServer string // https://host:port
	Client    *http.Client
	TokenFile string // pathops-events' own API token (re-read on every review: the kubelet rotates it)

	Audience  string        // pathops-events
	Publisher string        // system:serviceaccount:<namespace>:<name>
	Issuer    string        // the cluster's ServiceAccount issuer
	MaxTTL    time.Duration // the longest token lifetime (exp - iat) accepted
	Now       func() time.Time
}

// NewClient is the API server client: TLS with exactly the cluster CA.
func NewClient(caFile string) (*http.Client, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("no CA certificate in " + caFile)
	}
	return &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}, nil
}

type tokenReview struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Token     string   `json:"token"`
		Audiences []string `json:"audiences"`
	} `json:"spec"`
	Status struct {
		Authenticated bool `json:"authenticated"`
		User          struct {
			Username string `json:"username"`
		} `json:"user"`
		Audiences []string `json:"audiences"`
	} `json:"status"`
}

// Verify returns the publisher's username when token is its valid token.
func (v *Verifier) Verify(ctx context.Context, token string) (string, error) {
	if token == "" || len(token) > MaxTokenLength {
		return "", ErrUnauthenticated
	}
	// The claims are checked first (no API call for a token that cannot
	// pass), and trusted only because the review then accepts the token.
	if err := v.claims(token); err != nil {
		return "", err
	}
	own, err := os.ReadFile(v.TokenFile)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var req tokenReview
	req.APIVersion, req.Kind = "authentication.k8s.io/v1", "TokenReview"
	req.Spec.Token, req.Spec.Audiences = token, []string{v.Audience}
	body, _ := json.Marshal(req)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, v.APIServer+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(own)))
	resp, err := v.Client.Do(r)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: TokenReview answered %d", ErrUnavailable, resp.StatusCode)
	}
	var res tokenReview
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&res); err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	st := res.Status
	if !st.Authenticated || !slices.Contains(st.Audiences, v.Audience) || st.User.Username != v.Publisher {
		return "", ErrUnauthenticated
	}
	return st.User.Username, nil
}

// claims checks the token's issuer, audience and lifetime.
func (v *Verifier) claims(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrUnauthenticated
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ErrUnauthenticated
	}
	var c struct {
		Issuer   string          `json:"iss"`
		Audience json.RawMessage `json:"aud"`
		Expiry   *int64          `json:"exp"`
		IssuedAt *int64          `json:"iat"`
	}
	if json.Unmarshal(raw, &c) != nil || c.Expiry == nil || c.IssuedAt == nil {
		return ErrUnauthenticated
	}
	var aud []string
	if json.Unmarshal(c.Audience, &aud) != nil {
		var one string
		if json.Unmarshal(c.Audience, &one) != nil {
			return ErrUnauthenticated
		}
		aud = []string{one}
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	exp, iat := time.Unix(*c.Expiry, 0), time.Unix(*c.IssuedAt, 0)
	switch {
	case c.Issuer != v.Issuer, len(aud) != 1 || aud[0] != v.Audience:
		return ErrUnauthenticated
	case !now().Before(exp), exp.Sub(iat) > v.MaxTTL, !iat.Before(exp):
		return ErrUnauthenticated
	}
	return nil
}
