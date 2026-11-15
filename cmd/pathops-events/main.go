// Command pathops-events runs pathops-events (Decision 0063): the Cell's
// live-update channel. Browsers of signed-in people (the Cell's Dex) hold one
// Server-Sent Events stream each; the Tenant Control Plane publishes small
// invalidations on an internal listener with a short-lived ServiceAccount
// token; each one reaches the streams of the person it names. It keeps no
// domain state: REST stays the source of truth. One replica, in memory. The
// configuration comes from the environment (internal/config).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/PathOps/pathops-events/internal/config"
	"github.com/PathOps/pathops-events/internal/hub"
	"github.com/PathOps/pathops-events/internal/human"
	"github.com/PathOps/pathops-events/internal/server"
	"github.com/PathOps/pathops-events/internal/workload"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("pathops-events failed", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	shutdownTimeout := flag.Duration("shutdown-timeout", 10*time.Second, "graceful shutdown timeout")
	flag.Parse()

	secret, err := os.ReadFile(cfg.OIDCSecretFile)
	if err != nil {
		return err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.OIDCCAFile != "" {
		ca, err := os.ReadFile(cfg.OIDCCAFile)
		if err != nil {
			return err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(ca) {
			return errors.New("PATHOPS_EVENTS_OIDC_CA_FILE holds no certificate")
		}
		tr.TLSClientConfig.RootCAs = roots
	}
	people, err := human.New(human.Config{Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID,
		ClientSecret: strings.TrimSpace(string(secret)), PublicURL: cfg.PublicURL,
		HTTP: &http.Client{Timeout: 10 * time.Second, Transport: tr}})
	if err != nil {
		return err
	}
	kube, err := workload.NewClient(cfg.KubernetesCAFile)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return err
	}
	h := &hub.Hub{}
	s := &server.Server{Hub: h, People: people,
		Publishers: &workload.Verifier{APIServer: cfg.KubernetesURL, Client: kube, TokenFile: cfg.KubernetesTokenFile,
			Audience: cfg.Audience, Publisher: cfg.Publisher, Issuer: cfg.TokenIss, MaxTTL: cfg.MaxTTL},
		PublicURL: cfg.PublicURL, AllowedOrigin: cfg.AllowedOrigin, Issuer: cfg.OIDCIssuer,
		Heartbeat: cfg.Heartbeat, Retry: 5 * time.Second, Log: log}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("configuration", "publicUrl", cfg.PublicURL, "allowedOrigin", cfg.AllowedOrigin, "oidcIssuer", cfg.OIDCIssuer,
		"oidcClientId", cfg.OIDCClientID, "audience", cfg.Audience, "publisher", cfg.Publisher, "publisherIssuer", cfg.TokenIss,
		"publisherMaxTtl", cfg.MaxTTL.String(), "heartbeat", cfg.Heartbeat.String(),
		"public", cfg.PublicAddress, "internal", cfg.InternalAddress)

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	// No write timeout on either: a stream lasts as long as its browser
	// (each write has its own deadline), and a publish is small.
	servers := []*http.Server{
		{Addr: cfg.PublicAddress, Handler: s.Public(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second, TLSConfig: tlsConfig},
		{Addr: cfg.InternalAddress, Handler: s.Internal(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			IdleTimeout: 120 * time.Second, TLSConfig: tlsConfig},
	}
	errc := make(chan error, len(servers))
	for _, srv := range servers {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			return err
		}
		go func() { errc <- srv.ServeTLS(ln, "", "") }()
		log.Info("listening", "addr", ln.Addr().String())
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	// Streams end first (browsers reconnect to the next replica start).
	log.Info("shutting down", "timeout", shutdownTimeout.String(), "streams", h.Len())
	h.Close()
	sctx, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(sctx); err != nil {
			return err
		}
	}
	return nil
}
