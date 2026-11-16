package config

import (
	"strings"
	"testing"
	"time"
)

func env(over map[string]string) func(string) string {
	base := map[string]string{
		"TLS_CERT_FILE":                          "/tls/tls.crt",
		"TLS_KEY_FILE":                           "/tls/tls.key",
		"PATHOPS_EVENTS_PUBLIC_URL":              "https://events-acme.demo.pathops.io",
		"PATHOPS_EVENTS_ALLOWED_ORIGIN":          "https://control-plane-acme.demo.pathops.io",
		"PATHOPS_EVENTS_OIDC_ISSUER":             "https://dex-acme.demo.pathops.io",
		"PATHOPS_EVENTS_OIDC_CLIENT_SECRET_FILE": "/oidc/client-secret",
		"PATHOPS_EVENTS_SESSION_KEY_FILE":        "/session/key",
		"PATHOPS_EVENTS_PUBLISHER":               "system:serviceaccount:pathops-system:tenant-control-plane",
		"PATHOPS_EVENTS_PUBLISHER_ISSUER":        "https://kubernetes.default.svc.cluster.local",
		"PATHOPS_EVENTS_KUBERNETES_CA_FILE":      "/kubernetes/ca.crt",
		"PATHOPS_EVENTS_KUBERNETES_TOKEN_FILE":   "/kubernetes-token/token",
		"KUBERNETES_SERVICE_HOST":                "10.96.0.1",
		"KUBERNETES_SERVICE_PORT":                "443",
	}
	for k, v := range over {
		base[k] = v
	}
	return func(k string) string { return base[k] }
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicAddress != ":8443" || c.InternalAddress != ":9443" || c.Audience != "pathops-events" || c.OIDCClientID != "pathops-events-web" ||
		c.MaxTTL != time.Hour || c.Heartbeat != 25*time.Second || c.KubernetesURL != "https://10.96.0.1:443" {
		t.Fatalf("%+v", c)
	}
}

func TestInvalid(t *testing.T) {
	for name, over := range map[string]map[string]string{
		"no TLS":                 {"TLS_KEY_FILE": ""},
		"same listeners":         {"PATHOPS_EVENTS_INTERNAL_ADDRESS": ":8443"},
		"public URL with a path": {"PATHOPS_EVENTS_PUBLIC_URL": "https://events-acme.demo.pathops.io/x"},
		"http origin":            {"PATHOPS_EVENTS_ALLOWED_ORIGIN": "http://control-plane-acme.demo.pathops.io"},
		"no secret":              {"PATHOPS_EVENTS_OIDC_CLIENT_SECRET_FILE": ""},
		"no session key":         {"PATHOPS_EVENTS_SESSION_KEY_FILE": ""},
		"publisher not an SA":    {"PATHOPS_EVENTS_PUBLISHER": "tenant-control-plane"},
		"publisher issuer":       {"PATHOPS_EVENTS_PUBLISHER_ISSUER": ""},
		"audience is the client": {"PATHOPS_EVENTS_AUDIENCE": "pathops-events-web"},
		"not in a cluster":       {"KUBERNETES_SERVICE_HOST": ""},
		"no own token":           {"PATHOPS_EVENTS_KUBERNETES_TOKEN_FILE": ""},
		"heartbeat too long":     {"PATHOPS_EVENTS_HEARTBEAT": "5m"},
		"bad TTL":                {"PATHOPS_EVENTS_PUBLISHER_MAX_TTL": "soon"},
	} {
		if _, err := Load(env(over)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.TrimSpace(err.Error()) == "" {
			t.Errorf("%s: no reason", name)
		}
	}
}
