package main

import (
	"beacon/internal/beacon"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func csvEnv(key string) []string {
	var out []string
	for _, value := range strings.Split(os.Getenv(key), ",") {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}
func run() error {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		fmt.Println(beacon.RandomHex(32))
		return nil
	}
	if len(os.Args) > 1 && (os.Args[1] == "backup-encrypt" || os.Args[1] == "backup-decrypt") {
		key, e := beacon.KeyFromHex(secret("BEACON_BACKUP_KEY"))
		if e != nil {
			return e
		}
		if os.Args[1] == "backup-encrypt" {
			return beacon.EncryptBackup(os.Stdin, os.Stdout, key)
		}
		return beacon.DecryptBackup(os.Stdin, os.Stdout, key)
	}
	key, e := beacon.KeyFromHex(secret("BEACON_KEY"))
	if e != nil {
		return e
	}
	crypto, e := beacon.NewCrypto(key)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	s, e := beacon.OpenStore(ctx, secret("DATABASE_URL"), crypto)
	if e != nil {
		return fmt.Errorf("database connection failed: %w", e)
	}
	defer s.DB.Close()
	if len(os.Args) > 1 && os.Args[1] == "audit" {
		n, hash, e := s.Verify(ctx)
		if e != nil {
			return e
		}
		fmt.Printf("Verified %d events\nCheckpoint: %s\n", n, hash)
		return nil
	}
	if len(os.Args) > 1 && os.Args[1] == "verify-data" {
		n, e := s.VerifyData(ctx)
		if e != nil {
			return e
		}
		fmt.Printf("Verified %d encrypted cases and their evidence hashes\n", n)
		return nil
	}

	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	if command == "rotate-key" {
		nextKey, e := beacon.KeyFromHex(secret("BEACON_NEW_KEY"))
		if e != nil {
			return e
		}
		next, e := beacon.NewCrypto(nextKey)
		if e != nil {
			return e
		}
		if e = s.RotateKey(ctx, next); e != nil {
			return e
		}
		fmt.Println("Key rotated atomically. Replace the active key file before restarting; preserve old backup keys.")
		return nil
	}
	if command == "migrate" || os.Getenv("BEACON_DEV") == "true" {
		if e = s.Migrate(ctx); e != nil {
			return e
		}
		if e = s.Bootstrap(ctx, strings.ToLower(os.Getenv("BEACON_ADMIN_EMAIL")), secret("BEACON_ADMIN_PASSWORD")); e != nil {
			return e
		}
	} else {
		if e = s.Ready(ctx); e != nil {
			return e
		}
	}
	if command == "migrate" {
		fmt.Println("Migrations verified and applied")
		return nil
	}
	if command == "seed-demo" {
		if os.Getenv("BEACON_DEV") != "true" {
			return fmt.Errorf("demo seeding requires development mode")
		}
		return beacon.SeedDemo(ctx, s)
	}
	if command != "serve" {
		return fmt.Errorf("unknown command")
	}

	expires, e := time.Parse(time.RFC3339, os.Getenv("BEACON_SECURITY_EXPIRES"))
	if e != nil {
		return fmt.Errorf("Set BEACON_SECURITY_EXPIRES to an explicit RFC3339 timestamp")
	}
	smtpRoots, e := beacon.LoadSMTPRootCAs(os.Getenv("BEACON_SMTP_CA_FILE"))
	if e != nil {
		return fmt.Errorf("SMTP CA configuration failed: %w", e)
	}
	config := beacon.Config{URL: env("BEACON_URL", "http://localhost:8787"), Organization: env("BEACON_ORG", "Your organization"), Listen: env("BEACON_LISTEN", "127.0.0.1:8787"), Dev: os.Getenv("BEACON_DEV") == "true", Expires: expires, Policy: os.Getenv("BEACON_POLICY"), TrustedProxyCIDRs: csvEnv("BEACON_TRUSTED_PROXY_CIDRS"), SMTP: beacon.SMTPConfig{Address: os.Getenv("BEACON_SMTP_ADDR"), Username: os.Getenv("BEACON_SMTP_USER"), Password: secret("BEACON_SMTP_PASSWORD"), From: os.Getenv("BEACON_SMTP_FROM"), TLSRootCAs: smtpRoots}, OIDC: beacon.OIDCConfig{Issuer: os.Getenv("BEACON_OIDC_ISSUER"), ClientID: os.Getenv("BEACON_OIDC_CLIENT_ID"), ClientSecret: secret("BEACON_OIDC_CLIENT_SECRET"), RequiredACR: os.Getenv("BEACON_OIDC_ACR")}}
	if !config.Dev {
		if e = s.CheckRuntimeRole(ctx); e != nil {
			return e
		}
	}
	app, e := beacon.NewApp(s, config)
	if e != nil {
		return e
	}
	server := &http.Server{Addr: config.Listen, Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	workerCtx, stopWorker := context.WithCancel(context.Background())
	defer stopWorker()
	var sender beacon.MailSender
	if config.SMTP.Address != "" {
		if e = config.SMTP.Validate(); e != nil {
			return e
		}
		sender = config.SMTP
	}
	go s.RunWorker(workerCtx, sender, config.URL)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()
	slog.Info("Beacon started", "url", config.URL, "version", beacon.Version, "development", config.Dev)
	e = server.ListenAndServe()
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
func main() {
	if e := run(); e != nil {
		slog.Error("Beacon stopped", "error", e)
		os.Exit(1)
	}
}

func secret(name string) string {
	if path := os.Getenv(name + "_FILE"); path != "" {
		if os.Getenv(name) != "" {
			panic("use a secret value or secret file, not both")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			panic("cannot read configured secret file")
		}
		return strings.TrimSpace(string(b))
	}
	return os.Getenv(name)
}
