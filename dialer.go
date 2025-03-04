package ttproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/dunglas/httpsfv"
	"golang.org/x/net/proxy"
)

const (
	RequestProtocol = "connect-udp"

	ConnectUDPBindHeader     = "Connect-Udp-Bind"
	ProxyPublicAddressHeader = "Proxy-Public-Address"

	CompressionAssignValue = 0x1C0FE323
	CompressionCloseValue  = 0x1C0FE324
)

var (
	CapsuleProtocolHeaderValue string
	ConnectUDPBindHeaderValue  string
)

func init() {
	str, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal capsule protocol header value: %v", err))
	}
	CapsuleProtocolHeaderValue = str
	ConnectUDPBindHeaderValue = str
}

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
	// req.Header.Add("Authorization", srv.BasicAuth)
	req.Header.Add("Proxy-Authorization", srv.BasicAuth)

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
	req.Header.Add("Upgrade", "connect-udp")
	// req.Header.Add("Authorization", srv.BasicAuth)
	req.Header.Add("Proxy-Authorization", srv.BasicAuth)
	req.Header.Add("Connect-Udp-Bind", ConnectUDPBindHeaderValue)

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

var _ proxy.Dialer = (*tlsDialer)(nil)
