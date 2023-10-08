package main

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

type Config struct {
	User    string
	Servers []ServerConfig
}

type ServerConfig struct {
	Protocol        string
	Host            string
	Port            int
	RedirectToHTTPS bool
	ACMEChallenge   *ACMEChallengeConfig
	TLSCertFile     string
	TLSKeyFile      string
	Proxies         []ProxyConfig
}

type ACMEChallengeConfig struct {
	Root string
}

type ProxyConfig struct {
	Name string
	From ProxyFromConfig
	To   ProxyToConfig
}

type ProxyFromConfig struct {
	Host string
	Path string
}

type ProxyToConfig struct {
	Host string
	Port int
}

type InternalHCLConfig struct {
	User    string                    `hcl:"user,optional"`
	Servers []InternalHCLServerConfig `hcl:"server,block"`
}

type InternalHCLServerConfig struct {
	Protocol        string                           `hcl:"protocol,label"`
	Host            string                           `hcl:"host"`
	Port            int                              `hcl:"port"`
	RedirectToHTTPS bool                             `hcl:"redirect_to_https,optional"`
	ACMEChallenge   []InternalHCLACMEChallengeConfig `hcl:"acme_challenge,block"`
	TLSCertFile     string                           `hcl:"tls_cert_file,optional"`
	TLSKeyFile      string                           `hcl:"tls_key_file,optional"`
	Proxies         []InternalHCLProxyConfig         `hcl:"proxy,block"`
}

type InternalHCLACMEChallengeConfig struct {
	Root string `hcl:"root"`
}

type InternalHCLProxyConfig struct {
	Name string                     `hcl:"name,label"`
	From InternalHCLProxyFromConfig `hcl:"from,block"`
	To   InternalHCLProxyToConfig   `hcl:"to,block"`
}

type InternalHCLProxyFromConfig struct {
	Host string `hcl:"host,optional"`
	Path string `hcl:"path,optional"`
}

type InternalHCLProxyToConfig struct {
	Host string `hcl:"host"`
	Port int    `hcl:"port"`
}

func fromHCLConfigToConfig(hclConfig *InternalHCLConfig) *Config {
	servers := make([]ServerConfig, len(hclConfig.Servers))
	for i, s := range hclConfig.Servers {
		var acmeChallenge *ACMEChallengeConfig
		if len(s.ACMEChallenge) != 0 {
			acmeChallenge = &ACMEChallengeConfig{
				Root: s.ACMEChallenge[0].Root,
			}
		}
		proxies := make([]ProxyConfig, len(s.Proxies))
		for j, p := range s.Proxies {
			proxies[j] = ProxyConfig{
				Name: p.Name,
				From: ProxyFromConfig{
					Host: p.From.Host,
					Path: p.From.Path,
				},
				To: ProxyToConfig{
					Host: p.To.Host,
					Port: p.To.Port,
				},
			}
		}
		servers[i] = ServerConfig{
			Protocol:        s.Protocol,
			Host:            s.Host,
			Port:            s.Port,
			RedirectToHTTPS: s.RedirectToHTTPS,
			ACMEChallenge:   acmeChallenge,
			TLSCertFile:     s.TLSCertFile,
			TLSKeyFile:      s.TLSKeyFile,
			Proxies:         proxies,
		}
	}

	return &Config{
		User:    hclConfig.User,
		Servers: servers,
	}
}

func LoadConfig(fileName string) (*Config, error) {
	var hclConfig InternalHCLConfig
	err := hclsimple.DecodeFile(fileName, nil, &hclConfig)
	if err != nil {
		return nil, err
	}

	if len(hclConfig.Servers) == 0 {
		return nil, fmt.Errorf("No server blocks found")
	}
	if 2 < len(hclConfig.Servers) {
		return nil, fmt.Errorf("Too many server blocks found")
	}

	var listenHTTPS = false
	var redirectToHTTPS = false
	for _, server := range hclConfig.Servers {
		if server.Protocol == "https" {
			listenHTTPS = true
		} else if server.Protocol != "http" {
			return nil, fmt.Errorf("Invalid protocol %s", server.Protocol)
		}

		_, err = netip.ParseAddr(server.Host)
		if err != nil {
			return nil, fmt.Errorf("Invalid host %s", server.Host)
		}

		if len(server.ACMEChallenge) != 0 && len(server.ACMEChallenge) != 1 {
			return nil, fmt.Errorf("Only one acme_challenge block is allowed")
		}
		if len(server.ACMEChallenge) != 0 && server.Protocol != "http" {
			return nil, fmt.Errorf("accept_acme_challenge must be on http listener")
		}

		if server.RedirectToHTTPS {
			redirectToHTTPS = true
			if server.Protocol != "http" {
				return nil, fmt.Errorf("redirect_to_https must be on http listener")
			}
			if len(server.Proxies) != 0 {
				return nil, fmt.Errorf("redirect_to_https cannot be used with proxy")
			}
		}

		if server.Protocol == "https" {
			if server.TLSCertFile == "" {
				return nil, fmt.Errorf("tls_cert_file is required for https listener")
			}
			if server.TLSKeyFile == "" {
				return nil, fmt.Errorf("tls_key_file is required for https listener")
			}
		} else {
			if server.TLSCertFile != "" {
				return nil, fmt.Errorf("tls_cert_file is only allowed for https listener")
			}
			if server.TLSKeyFile != "" {
				return nil, fmt.Errorf("tls_key_file is only allowed for https listener")
			}
		}

		for _, p := range server.Proxies {
			if p.From.Path != "" {
				if !strings.HasPrefix(p.From.Path, "/") {
					return nil, fmt.Errorf("Path must start with '/'")
				}
				if !strings.HasSuffix(p.From.Path, "/") {
					return nil, fmt.Errorf("Path must end with '/'")
				}
			}
			if p.From.Host == "" && p.From.Path == "" {
				return nil, fmt.Errorf("Either host or path must be specified")
			}
			_, err := url.Parse(fmt.Sprintf("http://%s:%d", p.To.Host, p.To.Port))
			if err != nil {
				return nil, fmt.Errorf("Invalid host or port: %s:%d", p.To.Host, p.To.Port)
			}
		}
	}
	if redirectToHTTPS && !listenHTTPS {
		return nil, fmt.Errorf("redirect_to_https requires https listener")
	}

	return fromHCLConfigToConfig(&hclConfig), nil
}
