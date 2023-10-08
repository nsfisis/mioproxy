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
	ret := true
	if r.fromHost != "" {
		ret = ret && r.fromHost == host
	}
	if r.fromPath != "" {
		ret = ret && strings.HasPrefix(path+"/", r.fromPath)
	}
	return ret
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

func newMultipleReverseProxyServer(ps []ProxyConfig) (*multipleReverseProxyServer, error) {
	var rules []rewriteRule
	for _, p := range ps {
		targetUrl, err := url.Parse(fmt.Sprintf("http://%s:%d", p.To.Host, p.To.Port))
		if err != nil {
			return nil, err
		}
		var proxy http.Handler = &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(targetUrl)
				r.SetXForwarded()
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
	hostWithoutPort string,
) bool {
	for _, rule := range s.rules {
		if rule.matches(hostWithoutPort, r.URL.Path) {
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
		reverseProxyServer, err := newMultipleReverseProxyServer(cfg.Proxies)
		if err != nil {
			return nil, err
		}
		h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// r.Host may have ":port" part.
			hostWithoutPort, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				http.Error(w, "400 invalid host", http.StatusBadRequest)
				return
			}
			found := reverseProxyServer.tryServeHTTP(w, r, hostWithoutPort)
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
			Addr:      fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Handler:   h,
			TLSConfig: tlsConfig,
		},
	}, nil
}

func (s *Server) Label() string {
	return s.s.Addr
}

func (s *Server) Serve(listener net.Listener) error {
	if s.tlsEnabled {
		return s.s.ServeTLS(listener, "", "")
	} else {
		return s.s.Serve(listener)
	}
}

func (s *Server) Shutdown(ctx context.Context) {
	s.s.Shutdown(ctx)
}

func NewListener(cfg *ServerConfig) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.Host, cfg.Port))
}
