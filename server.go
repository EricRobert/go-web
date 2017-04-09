package web

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Server implements an HTTPS server on the specified port.
// If a managed host is specified, the certificate is requested from letsencrypt.org and kept in cache.
// A certificate/key pair can also be specified.
// When deployed, this server gets 'A+' from https://www.ssllabs.com/ssltest
// The server will shutdown on SIGTERM or SIGINT signals.
type Server struct {
	// Handler responds to HTTP requests.
	// Will invoke the io.Closer interface if implemented.
	Handler http.Handler
	// Address indicates the address of the server.
	Address string
	// Certificate contains the location of the public SSL certificate.
	// Can be specified with $HTTPS_CRT.
	Certificate string
	// Key contains the location of the matching private key of the SSL certificate.
	// Can be specified with $HTTPS_KEY.
	Key string
	// Host contains the exact domain name.
	// When specified, the certificate will be requested from letsencrypt.org.
	// Can be specified with $HTTPS_HOST.
	// Multiple hosts are supported using a comma separated list.
	Host string
	// Cache contains the location where the requested certificate will be stored.
	// Will use "$HOME/certs" if empty.
	Cache string
	// Timeout indicates the maximum allowed time for shutdown.
	// Will use 5 seconds by default.
	Timeout time.Duration
}

// ListenAndServe installs an HTTPS server with the specified parameters.
func (s Server) ListenAndServe() (err error) {
	c := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	host := s.Host
	if host == "" {
		host = os.ExpandEnv("$HTTPS_HOST")
	}

	if host != "" {
		hosts := strings.Split(host, ",")

		dir := s.Cache
		if dir == "" {
			dir = os.ExpandEnv("$HOME/certs")
		}

		certs := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hosts...),
			Cache:      autocert.DirCache(dir),
		}

		c.GetCertificate = certs.GetCertificate
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		if s.Handler != nil {
			s.Handler.ServeHTTP(w, r)
		}
	})

	server := &http.Server{
		Addr:         s.Address,
		Handler:      h,
		TLSConfig:    c,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  90 * time.Second,
	}

	done := make(chan error, 1)

	go func() {
		crt := s.Certificate
		if crt == "" {
			crt = os.ExpandEnv("$HTTPS_CRT")
		}

		key := s.Key
		if key == "" {
			key = os.ExpandEnv("$HTTPS_KEY")
		}

		secure := host != "" || (crt != "" && key != "")

		addr := os.ExpandEnv("$HTTPS_BIND")
		if addr == "" {
			addr = ":http"

			if secure {
				addr = ":https"
			}
		}

		if server.Addr == "" {
			server.Addr = addr
		}

		log.Println("server address is", server.Addr)

		if secure {
			done <- server.ListenAndServeTLS(crt, key)
		} else {
			done <- server.ListenAndServe()
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err = <-done:
		return
	case <-signals:
	}

	log.Println("closing...")

	go func() {
		<-signals
		log.Fatalln("killed.")
	}()

	timeout := s.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	ctx, _ := context.WithTimeout(context.Background(), timeout)
	if err = server.Shutdown(ctx); err != nil {
		return
	}

	if s.Handler != nil {
		if h, ok := s.Handler.(io.Closer); ok {
			err = h.Close()
		}
	}

	log.Println("done.")
	return
}
