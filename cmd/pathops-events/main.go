// Command pathops-events runs pathops-events (Decision 0063): the Cell's
// live-update channel. Browsers of signed-in people hold one Socket.IO
// connection each, authenticated by the PathOps token the UI already holds
// for the Tenant CP; the Tenant Control Plane publishes small invalidations on
// an internal listener with a short-lived ServiceAccount token; each one
// reaches the connections of the person it names. It keeps no
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
	"syscall"
	"time"

	siolog "github.com/zishang520/socket.io/v3/pkg/log"

	"github.com/PathOps/pathops-events/internal/config"
	"github.com/PathOps/pathops-events/internal/hub"
	"github.com/PathOps/pathops-events/internal/server"
	"github.com/PathOps/pathops-events/internal/token"
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

	// The Socket.IO library's debug log prints handshakes and events (a
	// token among them): never on.
	siolog.DEBUG.Store(false)
	var roots *x509.CertPool
	if cfg.OIDCCAFile != "" {
		ca, err := os.ReadFile(cfg.OIDCCAFile)
		if err != nil {
			return err
		}
		if roots, err = x509.SystemCertPool(); err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(ca) {
			return errors.New("PATHOPS_EVENTS_OIDC_CA_FILE holds no certificate")
		}
	}
	people := token.NewVerifier(cfg.OIDCIssuer, cfg.TokenAudience, roots)
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
		AllowedOrigin: cfg.AllowedOrigin, Issuer: cfg.OIDCIssuer, Log: log}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("configuration", "allowedOrigin", cfg.AllowedOrigin, "oidcIssuer", cfg.OIDCIssuer,
		"tokenAudience", cfg.TokenAudience, "audience", cfg.Audience, "publisher", cfg.Publisher, "publisherIssuer", cfg.TokenIss,
		"publisherMaxTtl", cfg.MaxTTL.String(), "public", cfg.PublicAddress, "internal", cfg.InternalAddress)

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	// No write timeout on either: a browser connection lasts as long as its
	// token (Socket.IO's ping/pong finds dead ones), and a publish is small.
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
	// Connections end first (browsers reconnect to the next replica start).
	log.Info("shutting down", "timeout", shutdownTimeout.String(), "connections", h.Len())
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
