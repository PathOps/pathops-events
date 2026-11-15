package workload

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	tcp    = "system:serviceaccount:pathops-system:tenant-control-plane"
	k8sIss = "https://kubernetes.default.svc.cluster.local"
)

var now = time.Unix(1_800_000_000, 0)

// jwt is an unsigned token with claims (the fake API server decides
// validity, like the real one decides the signature).
func jwt(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(b) + ".c2ln"
}

func good(over map[string]any) string {
	c := map[string]any{"iss": k8sIss, "aud": []string{"pathops-events"}, "iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(), "sub": tcp}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return jwt(c)
}

// apiServer answers TokenReviews: a token it knows is authenticated as its
// username with its audiences; every other is not. It records the reviews.
type apiServer struct {
	users     map[string]string
	audiences []string
	reviews   int
	own       string
}

func (a *apiServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.reviews++
	if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" || r.Header.Get("Authorization") != "Bearer "+a.own {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var req tokenReview
	_ = json.NewDecoder(r.Body).Decode(&req)
	var res tokenReview
	if u, ok := a.users[req.Spec.Token]; ok && len(req.Spec.Audiences) == 1 && req.Spec.Audiences[0] == "pathops-events" {
		res.Status.Authenticated = true
		res.Status.User.Username = u
		res.Status.Audiences = a.audiences
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(res)
}

func verifier(t *testing.T, a *apiServer) *Verifier {
	srv := httptest.NewTLSServer(a)
	t.Cleanup(srv.Close)
	own := filepath.Join(t.TempDir(), "token")
	a.own = "own-token"
	if err := os.WriteFile(own, []byte(a.own+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Verifier{APIServer: srv.URL, Client: srv.Client(), TokenFile: own, Audience: "pathops-events", Publisher: tcp,
		Issuer: k8sIss, MaxTTL: time.Hour, Now: func() time.Time { return now }}
}

func TestPublisherAllowed(t *testing.T) {
	tok := good(nil)
	v := verifier(t, &apiServer{users: map[string]string{tok: tcp}, audiences: []string{"pathops-events"}})
	if u, err := v.Verify(context.Background(), tok); err != nil || u != tcp {
		t.Fatal(u, err)
	}
}

func TestDenied(t *testing.T) {
	other := "system:serviceaccount:pathops-system:pathops-frontend"
	cases := map[string]struct {
		token string
		user  string
		aud   []string
	}{
		"another ServiceAccount (wrong subject)": {good(nil), other, []string{"pathops-events"}},
		"a ServiceAccount of another namespace":  {good(nil), "system:serviceaccount:acme-ci:tenant-control-plane", []string{"pathops-events"}},
		"the review names another audience":      {good(nil), tcp, []string{"https://kubernetes.default.svc.cluster.local"}},
		"wrong audience in the token":            {good(map[string]any{"aud": []string{"pathops-artifact-store"}}), tcp, []string{"pathops-events"}},
		"an additional audience":                 {good(map[string]any{"aud": []string{"pathops-events", "zot"}}), tcp, []string{"pathops-events"}},
		"expired":                                {good(map[string]any{"iat": now.Add(-20 * time.Minute).Unix(), "exp": now.Add(-10 * time.Minute).Unix()}), tcp, []string{"pathops-events"}},
		"long-lived (a year)":                    {good(map[string]any{"exp": now.Add(365 * 24 * time.Hour).Unix()}), tcp, []string{"pathops-events"}},
		"no expiry":                              {good(map[string]any{"exp": nil}), tcp, []string{"pathops-events"}},
		"a person's Dex token (another issuer)":  {good(map[string]any{"iss": "https://dex-acme.demo.pathops.io", "aud": "pathops-events"}), tcp, []string{"pathops-events"}},
	}
	for name, c := range cases {
		a := &apiServer{users: map[string]string{c.token: c.user}, audiences: c.aud}
		v := verifier(t, a)
		if _, err := v.Verify(context.Background(), c.token); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Valid claims the API server does not authenticate (forged or of a
	// deleted Pod).
	v := verifier(t, &apiServer{users: map[string]string{}})
	if _, err := v.Verify(context.Background(), good(nil)); !errors.Is(err, ErrUnauthenticated) {
		t.Error("unauthenticated by the review:", err)
	}
}

func TestMalformedNeverReachesTheAPIServer(t *testing.T) {
	a := &apiServer{users: map[string]string{}}
	v := verifier(t, a)
	for _, tok := range []string{"", "x", "a.b", "a.!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("[1]")) + ".c",
		string(make([]byte, MaxTokenLength+1))} {
		if _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%.20q: %v", tok, err)
		}
	}
	if a.reviews != 0 {
		t.Fatalf("%d reviews", a.reviews)
	}
}

func TestReviewUnavailable(t *testing.T) {
	v := verifier(t, &apiServer{})
	v.TokenFile = filepath.Join(t.TempDir(), "missing")
	if _, err := v.Verify(context.Background(), good(nil)); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	v = verifier(t, &apiServer{})
	v.APIServer = "https://127.0.0.1:1"
	if _, err := v.Verify(context.Background(), good(nil)); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
