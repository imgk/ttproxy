package ttproxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/proxy"
)

const (
	RequestProtocol = "connect-udp"

	CapsuleProtocolHeader    = "Capsule-Protocol"
	ConnectUDPBindHeader     = "Connect-Udp-Bind"
	ProxyAuthorizationHeader = "Proxy-Authorization"
	ProxyPublicAddressHeader = "Proxy-Public-Address"

	CapsuleProtocolHeaderValue = "?1"
	ConnectUDPBindHeaderValue  = "?1"

	CompressionAssignValue = 0x1C0FE323
	CompressionCloseValue  = 0x1C0FE324
)

func init() {
	proxy.RegisterDialerType("https", newHTTPDialer)
}

// add customized http dialer to golang.org/x/net/proxy
type httpDialer struct {
	proxy.Dialer

	HostPort  string
	BasicAuth string

	tcpURL string
}

func newHTTPDialer(uri *url.URL, d proxy.Dialer) (proxy.Dialer, error) {
	dialer := &httpDialer{Dialer: d, HostPort: uri.Host}
	if user := uri.User.Username(); user != "" {
		if password, ok := uri.User.Password(); ok && password != "" {
			dialer.BasicAuth = "basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
		} else {
			return nil, fmt.Errorf("user name: %v and password: %v error", user, password)
		}
	}
	dialer.tcpURL = fmt.Sprintf("https://%s", dialer.HostPort)
	return dialer, nil
}

func (d *httpDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.Dial("tcp", d.HostPort)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodConnect, d.tcpURL, nil)
	if err != nil {
		return conn, fmt.Errorf("request error: %w", err)
	}
	req.URL.Opaque = addr
	// req.Header.Add("Authorization", srv.BasicAuth)
	if d.BasicAuth != "" {
		req.Header.Add("Proxy-Authorization", d.BasicAuth)
	}

	err = req.WriteProxy(conn)
	if err != nil {
		return conn, fmt.Errorf("write request error: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return conn, fmt.Errorf("read response error: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return conn, fmt.Errorf("server status code error: %v", resp.StatusCode)
	}
	return conn, nil
}

// a tls dialer with a proxy.Dialer embedded
type tlsDialer struct {
	proxy.Dialer
	tls.Config
}

func (d *tlsDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return net.Conn(tls.Client(conn, &d.Config)), nil
}

// a HTTP dialer which utilizes HTTP CONNECT method for TCP and RFC 9298 for UDP
func (srv Server) Dial(network, addr string) (net.Conn, error) {
	conn, err := srv.Dialer.Dial("tcp", srv.HostPort)
	if err != nil {
		return nil, err
	}

	switch network {
	case "tcp":
		conn, err = srv.dialTCP(conn, addr)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("dial tcp error: %w", err)
		}
		return conn, nil
	case "udp":
		conn, err = srv.dialUDP(conn, addr)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("dial udp error: %w", err)
		}
		return conn, nil
	default:
		conn.Close()
		return nil, fmt.Errorf("incorrect network type: %v", network)
	}
}

func (srv Server) dialTCP(conn net.Conn, addr string) (net.Conn, error) {
	req, err := http.NewRequest(http.MethodConnect, srv.tcpURL, nil)
	if err != nil {
		return conn, fmt.Errorf("request error: %w", err)
	}
	req.URL.Opaque = addr
	if srv.BasicAuth != "" {
		req.Header.Add(ProxyAuthorizationHeader, srv.BasicAuth)
	}

	err = req.WriteProxy(conn)
	if err != nil {
		return conn, fmt.Errorf("write request error: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return conn, fmt.Errorf("read response error: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return conn, fmt.Errorf("server status code error: %v", resp.StatusCode)
	}
	return conn, nil
}

func (srv Server) dialUDP(conn net.Conn, _ string) (net.Conn, error) {
	req, err := http.NewRequest(http.MethodGet, srv.udpURL, nil)
	if err != nil {
		return conn, fmt.Errorf("request error: %w", err)
	}
	req.Header.Add("Connection", "Upgrade")
	req.Header.Add("Upgrade", RequestProtocol)
	if srv.BasicAuth != "" {
		req.Header.Add(ProxyAuthorizationHeader, srv.BasicAuth)
	}
	req.Header.Add(CapsuleProtocolHeader, CapsuleProtocolHeaderValue)
	req.Header.Add(ConnectUDPBindHeader, ConnectUDPBindHeaderValue)

	err = req.WriteProxy(conn)
	if err != nil {
		return conn, fmt.Errorf("write request error: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return conn, fmt.Errorf("read response error: %w", err)
	}
	// slog.Info(fmt.Sprintf("header is %v", resp.Header))
	if str := resp.Header.Get("Connection"); str != "Upgrade" {
		return conn, fmt.Errorf("header Connection error: %v", str)
	}
	if str := resp.Header.Get("Upgrade"); str != "connect-udp" {
		// no Upgrade from server
		// return nil, fmt.Errorf("header Upgrade error: %v", str)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return conn, fmt.Errorf("server status code error: %v", resp.StatusCode)
	}
	return conn, nil
}

var (
	_ proxy.Dialer = (*tlsDialer)(nil)
	_ proxy.Dialer = (*httpDialer)(nil)
)
