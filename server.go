package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type multipleReverseProxyServer struct {
	rules []rewriteRule
}

type rewriteRule struct {
	fromHost string
	fromPath string
	toUrl    *url.URL
	proxy    http.Handler
}

func (r *rewriteRule) matches(host, path string) bool {
	if r.fromHost != "" {
		if r.fromHost != host {
			return false
		}
	}
	if r.fromPath != "" {
		if !strings.HasPrefix(path+"/", r.fromPath) {
			return false
		}
	}
	return true
}

func basicAuthHandler(handler http.Handler, realm, username, passwordHash string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inputUsername, inputPassword, ok := r.BasicAuth()
		if !ok || inputUsername != username || !VerifyPassword(inputPassword, passwordHash) {
			w.Header().Set(
				"WWW-Authenticate",
				fmt.Sprintf("Basic realm=\"%s\"", realm),
			)
			http.Error(w, "401 unauthorized", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func newMultipleReverseProxyServer(cfg *ServerConfig) (*multipleReverseProxyServer, error) {
	var rules []rewriteRule
	for _, p := range cfg.Proxies {
		targetUrl, err := url.Parse("http://" + net.JoinHostPort(p.To.Host, strconv.Itoa(p.To.Port)))
		if err != nil {
			return nil, err
		}
		var proxy http.Handler = &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(targetUrl)
				r.SetXForwarded()
			},
			ModifyResponse: func(r *http.Response) error {
				if r.StatusCode < 300 || 400 <= r.StatusCode {
					return nil
				}

				// If the response is redirect and has location header, rewrite it.
				location := r.Header.Get("Location")
				if location == "" {
					return nil
				}
				locationUrl, err := url.Parse(location)
				if err != nil {
					return nil
				}
				if !locationUrl.IsAbs() {
					return nil
				}
				if locationUrl.Hostname() != targetUrl.Hostname() {
					return nil
				}
				locationUrl.Host = p.From.Host
				if cfg.RedirectToHTTPS && locationUrl.Scheme == "http" {
					locationUrl.Scheme = "https"
				}
				r.Header.Set("Location", locationUrl.String())
				return nil
			},
		}
		if p.BasicAuth != nil {
			credentialFileContent, err := os.ReadFile(p.BasicAuth.CredentialFile)
			if err != nil {
				return nil, err
			}
			usernameAndPasswordHash := strings.Split(strings.TrimSuffix(string(credentialFileContent), "\n"), ":")
			if len(usernameAndPasswordHash) != 2 {
				return nil, fmt.Errorf("invalid credential file format")
			}
			username := usernameAndPasswordHash[0]
			passwordHash := usernameAndPasswordHash[1]
			proxy = basicAuthHandler(
				proxy,
				p.BasicAuth.Realm,
				username,
				passwordHash,
			)
		}
		rules = append(rules, rewriteRule{
			fromHost: p.From.Host,
			fromPath: p.From.Path,
			toUrl:    targetUrl,
			proxy:    proxy,
		})
	}
	return &multipleReverseProxyServer{
		rules: rules,
	}, nil
}

func (s *multipleReverseProxyServer) tryServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) bool {
	for _, rule := range s.rules {
		if rule.matches(r.Host, r.URL.Path) {
			rule.proxy.ServeHTTP(w, r)
			return true
		}
	}
	return false
}

type Server struct {
	s          http.Server
	tlsEnabled bool
}

func NewServer(cfg *ServerConfig) (*Server, error) {
	h := http.NewServeMux()

	if cfg.ACMEChallenge != nil {
		h.Handle(
			"/.well-known/acme-challenge/",
			http.FileServer(http.Dir(cfg.ACMEChallenge.Root)),
		)
	}

	if cfg.RedirectToHTTPS {
		h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			target := r.URL
			target.Scheme = "https"
			target.Host = r.Host
			http.Redirect(w, r, target.String(), http.StatusMovedPermanently)
		})
	} else {
		reverseProxyServer, err := newMultipleReverseProxyServer(cfg)
		if err != nil {
			return nil, err
		}
		h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			found := reverseProxyServer.tryServeHTTP(w, r)
			if !found {
				http.NotFound(w, r)
			}
		})
	}

	var tlsConfig *tls.Config
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}

	return &Server{
		tlsEnabled: cfg.Protocol == "https",
		s: http.Server{
			Addr:      fmt.Sprintf("%s:%d", strings.Join(cfg.Hosts, ","), cfg.Port),
			Handler:   h,
			TLSConfig: tlsConfig,
		},
	}, nil
}

func (s *Server) Label() string {
	return s.s.Addr
}

func (s *Server) Serve(listeners []net.Listener) error {
	errC := make(chan error, len(listeners))
	for _, l := range listeners {
		go func() {
			if s.tlsEnabled {
				errC <- s.s.ServeTLS(l, "", "")
			} else {
				errC <- s.s.Serve(l)
			}
		}()
	}
	return <-errC
}

func (s *Server) Shutdown(ctx context.Context) {
	s.s.Shutdown(ctx)
}

func NewListeners(cfg *ServerConfig) ([]net.Listener, error) {
	port := strconv.Itoa(cfg.Port)
	listeners := make([]net.Listener, 0, len(cfg.Hosts))
	for _, host := range cfg.Hosts {
		l, err := net.Listen("tcp", net.JoinHostPort(host, port))
		if err != nil {
			for _, prev := range listeners {
				prev.Close()
			}
			return nil, err
		}
		listeners = append(listeners, l)
	}
	return listeners, nil
}
