// Package config reads pathops-events' runtime configuration from the
// environment. Every value is validated at start; an invalid configuration
// stops the process before it listens.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Config is the runtime configuration.
type Config struct {
	// Two HTTPS listeners with the same certificate (the Cell CA leaf of
	// the public name and the Service's names): the public one (browsers,
	// through Traefik) and the internal one (publication by the Tenant CP,
	// on the Service only).
	PublicAddress   string // PATHOPS_EVENTS_PUBLIC_ADDRESS, default :8443
	InternalAddress string // PATHOPS_EVENTS_INTERNAL_ADDRESS, default :9443
	TLSCertFile     string // TLS_CERT_FILE
	TLSKeyFile      string // TLS_KEY_FILE

	// People: the PathOps human token (the access token the PathOps UI holds
	// for the Tenant CP), from the Cell's Dex, for the PathOps UI's client.
	AllowedOrigin string // PATHOPS_EVENTS_ALLOWED_ORIGIN: the PathOps UI, https://<controlPlane host>
	OIDCIssuer    string // PATHOPS_EVENTS_OIDC_ISSUER: the Cell's Dex
	OIDCCAFile    string // PATHOPS_EVENTS_OIDC_CA_FILE: optional roots for Dex (the Cell CA)
	TokenAudience string // PATHOPS_EVENTS_TOKEN_AUDIENCE, default pathops-ui (the PathOps UI's client)

	// Publishers: Kubernetes ServiceAccount tokens, reviewed by the API
	// server (TokenReview with Audience), of exactly Publisher.
	Audience  string        // PATHOPS_EVENTS_AUDIENCE, default pathops-events
	Publisher string        // PATHOPS_EVENTS_PUBLISHER: system:serviceaccount:<namespace>:<name>
	TokenIss  string        // PATHOPS_EVENTS_PUBLISHER_ISSUER: the cluster's ServiceAccount issuer
	MaxTTL    time.Duration // PATHOPS_EVENTS_PUBLISHER_MAX_TTL, default 1h: a longer-lived token is refused
	// The API server: in-cluster (KUBERNETES_SERVICE_HOST/PORT), with its CA
	// and pathops-events' own projected token (re-read on every review).
	KubernetesURL       string // from KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT
	KubernetesCAFile    string // PATHOPS_EVENTS_KUBERNETES_CA_FILE
	KubernetesTokenFile string // PATHOPS_EVENTS_KUBERNETES_TOKEN_FILE
}

var serviceAccount = regexp.MustCompile(`^system:serviceaccount:[a-z0-9]([-a-z0-9]*[a-z0-9])?:[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// Load reads the configuration through getenv.
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		PublicAddress:       or(getenv("PATHOPS_EVENTS_PUBLIC_ADDRESS"), ":8443"),
		InternalAddress:     or(getenv("PATHOPS_EVENTS_INTERNAL_ADDRESS"), ":9443"),
		TLSCertFile:         getenv("TLS_CERT_FILE"),
		TLSKeyFile:          getenv("TLS_KEY_FILE"),
		AllowedOrigin:       getenv("PATHOPS_EVENTS_ALLOWED_ORIGIN"),
		OIDCIssuer:          getenv("PATHOPS_EVENTS_OIDC_ISSUER"),
		OIDCCAFile:          getenv("PATHOPS_EVENTS_OIDC_CA_FILE"),
		TokenAudience:       or(getenv("PATHOPS_EVENTS_TOKEN_AUDIENCE"), "pathops-ui"),
		Audience:            or(getenv("PATHOPS_EVENTS_AUDIENCE"), "pathops-events"),
		Publisher:           getenv("PATHOPS_EVENTS_PUBLISHER"),
		TokenIss:            getenv("PATHOPS_EVENTS_PUBLISHER_ISSUER"),
		KubernetesCAFile:    getenv("PATHOPS_EVENTS_KUBERNETES_CA_FILE"),
		KubernetesTokenFile: getenv("PATHOPS_EVENTS_KUBERNETES_TOKEN_FILE"),
	}
	var errs []error
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		errs = append(errs, errors.New("TLS_CERT_FILE and TLS_KEY_FILE are required (pathops-events serves HTTPS only)"))
	}
	if c.PublicAddress == c.InternalAddress {
		errs = append(errs, errors.New("PATHOPS_EVENTS_PUBLIC_ADDRESS and PATHOPS_EVENTS_INTERNAL_ADDRESS must differ"))
	}
	if !origin(c.AllowedOrigin) {
		errs = append(errs, errors.New("PATHOPS_EVENTS_ALLOWED_ORIGIN must be https://<host> (the PathOps UI)"))
	}
	if !httpsURL(c.OIDCIssuer) {
		errs = append(errs, errors.New("PATHOPS_EVENTS_OIDC_ISSUER must be an https URL"))
	}
	if !serviceAccount.MatchString(c.Publisher) {
		errs = append(errs, errors.New("PATHOPS_EVENTS_PUBLISHER must be system:serviceaccount:<namespace>:<name>"))
	}
	if !httpsURL(c.TokenIss) {
		errs = append(errs, errors.New("PATHOPS_EVENTS_PUBLISHER_ISSUER must be an https URL (the cluster's ServiceAccount issuer)"))
	}
	// A person's token is never a publisher's, nor the reverse.
	if c.Audience == c.TokenAudience {
		errs = append(errs, errors.New("PATHOPS_EVENTS_AUDIENCE must differ from PATHOPS_EVENTS_TOKEN_AUDIENCE"))
	}
	if host, port := getenv("KUBERNETES_SERVICE_HOST"), getenv("KUBERNETES_SERVICE_PORT"); host != "" && port != "" {
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		c.KubernetesURL = "https://" + host + ":" + port
	} else {
		errs = append(errs, errors.New("KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are required (TokenReview)"))
	}
	if c.KubernetesCAFile == "" || c.KubernetesTokenFile == "" {
		errs = append(errs, errors.New("PATHOPS_EVENTS_KUBERNETES_CA_FILE and PATHOPS_EVENTS_KUBERNETES_TOKEN_FILE are required"))
	}
	var err error
	if c.MaxTTL, err = durationOr(getenv("PATHOPS_EVENTS_PUBLISHER_MAX_TTL"), time.Hour); err != nil {
		errs = append(errs, err)
	}
	return c, errors.Join(errs...)
}

func httpsURL(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// origin: https://<host>, nothing else.
func origin(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func durationOr(v string, def time.Duration) (time.Duration, error) {
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q", v)
	}
	return d, nil
}
