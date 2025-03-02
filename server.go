package ttproxy

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	_ "net/http/pprof"

	"golang.org/x/net/proxy"
)

type Config struct {
	Auth       proxy.Auth
	HostPort   string
	TProxyAddr string
	Timeout    time.Duration
	EnableTLS  bool
	PProf      bool
}

type Server struct {
	Config
	Dialer proxy.Dialer

	Host      string
	Port      string
	BasicAuth string

	tcpURL string
	udpURL string
}

func (srv *Server) Serve(cfg Config) error {
	srv.Config = cfg

	srv.Dialer = proxy.Direct
	if strs := strings.Split(srv.HostPort, ";"); len(strs) > 1 {
		for _, vv := range strs[:len(strs)-1] {
			uri, err := url.Parse(vv)
			if err != nil {
				return fmt.Errorf("parse uri: %v, error: %v", vv, err)
			}

			srv.Dialer, err = proxy.FromURL(uri, srv.Dialer)
			if err != nil {
				return fmt.Errorf("proxy from url: %v, error: %v", uri.String(), err)
			}
		}
		srv.HostPort = strs[len(strs)-1]
	} else {
		srv.Dialer = proxy.FromEnvironment()
	}

	host, port, err := net.SplitHostPort(srv.HostPort)
	if err != nil {
		return fmt.Errorf("split host port error: %w", err)
	}
	srv.Host = host
	srv.Port = port

	if srv.Auth.User == "" {
		if srv.Auth.Password != "" {
			return fmt.Errorf("username and password error: %s:%s", srv.Auth.User, srv.Auth.Password)
		}
	} else {
		if srv.Auth.Password == "" {
			return fmt.Errorf("username and password error: %s:%s", srv.Auth.User, srv.Auth.Password)
		} else {
			srv.BasicAuth = "basic " + base64.StdEncoding.EncodeToString([]byte(srv.Auth.User+":"+srv.Auth.Password))
		}
	}

	srv.tcpURL = fmt.Sprintf("https://%s", srv.HostPort)
	srv.udpURL = fmt.Sprintf("https://%s/.well-known/masque/udp/*/*/", srv.HostPort)

	if srv.PProf {
		go http.ListenAndServe(":2025", nil)
	}

	if srv.TProxyAddr != "" {
		slog.Info("start tproxy server")

		go srv.ServeTProxyTCP()
		go srv.ServeTProxyUDP()
	}

	return nil
}
