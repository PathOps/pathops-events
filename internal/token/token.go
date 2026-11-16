// Package token authenticates people by the PathOps human token (Decision
// 0063): the access token the PathOps UI already holds for the Tenant Control
// Plane's REST API, presented once more in the Socket.IO handshake. It is the
// same contract the Tenant CP verifies (its internal/auth, of which this is a
// copy): a JWT the Cell's own Dex signed (RS256, a key Dex publishes through
// OIDC discovery -> jwks_uri), the Cell's issuer exactly, the PathOps UI's
// audience, a subject and a current validity window (exp, nbf, iat). An
// Operation Authorization Token, a token of any other client of the same Dex
// (the CLI's, Forgejo's, the Artifact Store's...) or anything else is refused:
// authentication fails closed. The token is never stored or logged.
package token

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Leeway is the clock skew allowed on exp, nbf and iat (the Tenant CP's).
const Leeway = 30 * time.Second

// Algorithms are the accepted signature algorithms: Dex's local signer issues
// RS256. Every other algorithm, "none" included, is rejected before any key
// is used.
var Algorithms = []jose.SignatureAlgorithm{jose.RS256}

// MaxLength bounds a token (Dex access tokens are about 1 KiB).
const MaxLength = 8 << 10

// OperationAuthorizationType is the JWS "typ" of an Operation Authorization
// Token (Decision 0050): it proves a consent to the Tenant CP and never
// authenticates a person.
const OperationAuthorizationType = "pathops-oat+jwt"

// The reasons a token is refused (logged by label, never sent to a browser).
var (
	ErrMalformed      = errors.New("malformed token")
	ErrAlgorithm      = errors.New("unsupported signature algorithm")
	ErrUnknownKey     = errors.New("unknown signing key")
	ErrSignature      = errors.New("invalid signature")
	ErrIssuer         = errors.New("issuer mismatch")
	ErrAudience       = errors.New("audience mismatch")
	ErrExpired        = errors.New("token expired")
	ErrNotYetValid    = errors.New("token not yet valid")
	ErrIssuedInFuture = errors.New("token issued in the future")
	ErrClaims         = errors.New("missing required claims")
	// ErrUnavailable: the issuer's keys cannot be obtained; the token was not
	// judged (the browser tries again later).
	ErrUnavailable = errors.New("issuer keys unavailable")
)

// Identity is the person a token names at the Cell's issuer, and until when
// the token is valid.
type Identity struct {
	Issuer, Subject string
	Expiry          time.Time
}

// Verifier verifies PathOps human tokens of one issuer and audience.
type Verifier struct {
	issuer, audience string
	keys             *keySet
	now              func() time.Time
}

// NewVerifier returns a Verifier for issuer and audience (the PathOps UI's
// client). roots are the CAs trusted for TLS to the issuer (nil: the system
// roots). No network access happens until the first token is verified.
func NewVerifier(issuer, audience string, roots *x509.CertPool) *Verifier {
	return newVerifier(issuer, audience, &http.Client{
		Timeout: fetchTimeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
			TLSHandshakeTimeout: 5 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, time.Now)
}

func newVerifier(issuer, audience string, client *http.Client, now func() time.Time) *Verifier {
	return &Verifier{issuer: issuer, audience: audience, keys: newKeySet(issuer, client, now), now: now}
}

// Verify validates raw and returns the person it names.
func (v *Verifier) Verify(ctx context.Context, raw string) (Identity, error) {
	if raw == "" || len(raw) > MaxLength {
		return Identity{}, ErrMalformed
	}
	tok, err := jwt.ParseSigned(raw, Algorithms)
	if err != nil {
		if _, perr := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{
			jose.HS256, jose.HS384, jose.HS512, jose.RS384, jose.RS512, jose.ES256, jose.ES384,
			jose.ES512, jose.PS256, jose.PS384, jose.PS512, jose.EdDSA,
		}); perr == nil {
			return Identity{}, ErrAlgorithm
		}
		return Identity{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(tok.Headers) != 1 || tok.Headers[0].KeyID == "" {
		return Identity{}, fmt.Errorf("%w: one signature with a kid is required", ErrMalformed)
	}
	h := tok.Headers[0]
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ == OperationAuthorizationType {
		return Identity{}, fmt.Errorf("%w: an operation authorization token is not an access token", ErrMalformed)
	}
	key, err := v.keys.key(ctx, h.KeyID)
	if err != nil {
		return Identity{}, err
	}
	if !key.Valid() || !key.IsPublic() || (key.Use != "" && key.Use != "sig") ||
		(key.Algorithm != "" && key.Algorithm != h.Algorithm) {
		return Identity{}, fmt.Errorf("%w: key %q is not a %s signing key", ErrUnknownKey, h.KeyID, h.Algorithm)
	}
	var c jwt.Claims
	if err := tok.Claims(key.Key, &c); err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	if c.Issuer == "" || c.Subject == "" || len(c.Audience) == 0 || c.Expiry == nil || c.IssuedAt == nil {
		return Identity{}, fmt.Errorf("%w: iss, sub, aud, exp and iat", ErrClaims)
	}
	err = c.ValidateWithLeeway(jwt.Expected{Issuer: v.issuer, AnyAudience: jwt.Audience{v.audience}, Time: v.now()}, Leeway)
	switch {
	case err == nil:
		return Identity{Issuer: c.Issuer, Subject: c.Subject, Expiry: c.Expiry.Time()}, nil
	case errors.Is(err, jwt.ErrInvalidIssuer):
		return Identity{}, fmt.Errorf("%w: %q", ErrIssuer, c.Issuer)
	case errors.Is(err, jwt.ErrInvalidAudience):
		return Identity{}, fmt.Errorf("%w: %q", ErrAudience, []string(c.Audience))
	case errors.Is(err, jwt.ErrExpired):
		return Identity{}, ErrExpired
	case errors.Is(err, jwt.ErrNotValidYet):
		return Identity{}, ErrNotYetValid
	case errors.Is(err, jwt.ErrIssuedInTheFuture):
		return Identity{}, ErrIssuedInFuture
	default:
		return Identity{}, fmt.Errorf("%w: %v", ErrClaims, err)
	}
}

// Reason is the stable log label of a verification error.
func Reason(err error) string {
	for _, r := range []struct {
		err   error
		label string
	}{
		{ErrUnavailable, "issuer_keys_unavailable"}, {ErrMalformed, "malformed"}, {ErrAlgorithm, "unsupported_algorithm"},
		{ErrUnknownKey, "unknown_key"}, {ErrSignature, "bad_signature"}, {ErrIssuer, "issuer_mismatch"},
		{ErrAudience, "audience_mismatch"}, {ErrExpired, "expired"}, {ErrNotYetValid, "not_yet_valid"},
		{ErrIssuedInFuture, "issued_in_future"}, {ErrClaims, "missing_claims"},
	} {
		if errors.Is(err, r.err) {
			return r.label
		}
	}
	return "invalid"
}
