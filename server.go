package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type multipleReverseProxyServer struct {
	rules []rewriteRule
}

type rewriteRule struct {
	fromHost string
	toUrl    *url.URL
	proxy    *httputil.ReverseProxy
}

func newMultipleReverseProxyServer(ps []ProxyConfig) *multipleReverseProxyServer {
	var rules []rewriteRule
	for _, p := range ps {
		targetUrl, err := url.Parse(fmt.Sprintf("http://%s:%d", p.To.Host, p.To.Port))
		if err != nil {
			// This setting should be validated when loading config.
			panic(err)
		}
		rules = append(rules, rewriteRule{
			fromHost: p.From.Host,
			toUrl:    targetUrl,
			proxy: &httputil.ReverseProxy{
				Rewrite: func(r *httputil.ProxyRequest) {
					r.SetURL(targetUrl)
					r.SetXForwarded()
				},
			},
		})
	}
	return &multipleReverseProxyServer{
		rules: rules,
	}
}

func (s *multipleReverseProxyServer) tryServeHTTP(w http.ResponseWriter, r *http.Request) bool {
	for _, rule := range s.rules {
		if r.Host == rule.fromHost {
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

func NewServer(cfg *ServerConfig) *Server {
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
		reverseProxyServer := newMultipleReverseProxyServer(cfg.Proxies)
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
			panic(err)
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
	}
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
