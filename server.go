package ttproxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/imgk/go-tproxy"
	"golang.org/x/net/proxy"

	"github.com/imgk/ttproxy/pkg/quicvarint"
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

func copyBuffer(w io.Writer, r io.Reader, buf []byte) (n int64, err error) {
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}
			n += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if !errors.Is(er, io.EOF) {
				err = er
			}
			break
		}
	}
	return n, err
}

type Payload interface {
	Send(io.Writer) error
}

type Datagram struct {
	Type    uint64
	Length  uint64
	Payload Payload
}

func (data *Datagram) Receive(r io.Reader) error {
	return data.ReceiveBuffer(r, make([]byte, 1024*32))
}

func (data *Datagram) ReceiveBuffer(r io.Reader, b []byte) error {
	err := error(nil)

	rr := quicvarint.NewReader(r)
	data.Type, err = quicvarint.Read(rr)
	if err != nil {
		return fmt.Errorf("receive datagram type error: %w", err)
	}

	data.Length, err = quicvarint.Read(rr)
	if err != nil {
		return fmt.Errorf("receive datagram length error: %w", err)
	}

	bb := b[:data.Length]
	_, err = io.ReadFull(r, bb)
	if err != nil {
		return fmt.Errorf("receive datagram payload error: %w", err)
	}

	data.Payload = &BytePayload{Payload: bb}

	return nil
}

func (data *Datagram) Send(w io.Writer) error {
	bb := quicvarint.Append(quicvarint.Append(make([]byte, 0, 16), data.Type), data.Length)
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send type, length error: %w", err)
	}

	err = data.Payload.Send(w)
	if err != nil {
		return fmt.Errorf("send UDP payload error: %w", err)
	}

	return nil
}

type BytePayload struct {
	Payload []byte
}

func (data *BytePayload) Send(w io.Writer) error {
	_, err := w.Write(data.Payload)
	return err
}

type CompressedPayload struct {
	ContextID uint64
	Payload   []byte
}

func (data *CompressedPayload) Send(w io.Writer) error {
	bb := quicvarint.Append(make([]byte, 0, 8), data.ContextID)
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send context id error: %w", err)
	}

	_, err = w.Write(data.Payload)
	if err != nil {
		return fmt.Errorf("send payload error: %w", err)
	}
	return nil
}

func (data *CompressedPayload) Parse(b []byte) error {
	id, nr, err := quicvarint.Parse(b)
	if err != nil {
		return err
	}
	data.ContextID = id
	data.Payload = b[nr:]
	return nil
}

func (data *CompressedPayload) Len() uint64 {
	return uint64(quicvarint.Len(data.ContextID)) + uint64(len(data.Payload))
}

type UncompressedPayload struct {
	ContextID uint64
	IPVersion uint8
	Addr      netip.Addr
	Port      uint16
	Payload   []byte
}

func (data *UncompressedPayload) Send(w io.Writer) error {
	bb := append(append(append(quicvarint.Append(make([]byte, 0, 32), data.ContextID), byte(data.IPVersion)),
		data.Addr.AsSlice()...), byte(data.Port>>8), byte(data.Port))
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send uncompressed payload header error: %w", err)
	}

	_, err = w.Write(data.Payload)
	if err != nil {
		return fmt.Errorf("send payload error: %w", err)
	}
	return nil
}

func (data *UncompressedPayload) Parse(b []byte) error {
	id, nr, err := quicvarint.Parse(b)
	if err != nil {
		return err
	}

	data.ContextID = id

	switch b[nr] { // IPVersion
	case 4:
		data.IPVersion = 4
		data.Addr = netip.AddrFrom4([4]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4]})
		data.Port = uint16(b[nr+5])<<8 | uint16(b[nr+6])
		data.Payload = b[nr+7:]
	case 6:
		data.IPVersion = 6
		data.Addr = netip.AddrFrom16(
			[16]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4],
				b[nr+5], b[nr+6], b[nr+7], b[nr+8],
				b[nr+9], b[nr+10], b[nr+11], b[nr+12],
				b[nr+13], b[nr+14], b[nr+15], b[nr+16]})
		data.Port = uint16(b[nr+17])<<8 | uint16(b[nr+18])
		data.Payload = b[nr+19:]
	default:
		return fmt.Errorf("not a valid IP version: %v", b[nr])
	}
	return nil
}

func (data *UncompressedPayload) Len() uint64 {
	switch data.IPVersion {
	case 4:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 4 + 2 + uint64(len(data.Payload))
	case 6:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 16 + 2 + uint64(len(data.Payload))
	}
	return 0
}

type CompressionAssignPayload struct {
	ContextID uint64
	IPVersion uint8
	Addr      netip.Addr
	Port      uint16
}

func (data *CompressionAssignPayload) Send(w io.Writer) error {
	bb := append(quicvarint.Append(make([]byte, 0, 32), data.ContextID), byte(data.IPVersion))
	if data.IPVersion != 0 {
		bb = append(append(bb, data.Addr.AsSlice()...), byte(data.Port>>8), byte(data.Port))
	}

	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send compression assign payload header error: %w", err)
	}

	return nil
}

func (data *CompressionAssignPayload) Parse(b []byte) error {
	id, nr, err := quicvarint.Parse(b)
	if err != nil {
		return err
	}

	data.ContextID = id

	switch b[nr] { // IPVersion
	case 0:
		if id != 2 {
			// use 2 for default uncompressed context id
			return fmt.Errorf("cannot use context id: %v as uncomressed id", id)
		}

		data.IPVersion = 0
	case 4:
		data.IPVersion = 4
		data.Addr = netip.AddrFrom4([4]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4]})
		data.Port = uint16(b[nr+5])<<8 | uint16(b[nr+6])
	case 6:
		data.IPVersion = 6
		data.Addr = netip.AddrFrom16(
			[16]byte{b[nr+1], b[nr+2], b[nr+3], b[nr+4],
				b[nr+5], b[nr+6], b[nr+7], b[nr+8],
				b[nr+9], b[nr+10], b[nr+11], b[nr+12],
				b[nr+13], b[nr+14], b[nr+15], b[nr+16]})
		data.Port = uint16(b[nr+17])<<8 | uint16(b[nr+18])
	default:
		return fmt.Errorf("not a valid IP version: %v", b[nr])
	}
	return nil
}

func (data *CompressionAssignPayload) Len() uint64 {
	switch data.IPVersion {
	case 0:
		// context id is 2
		return 1 + 1
	case 4:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 4 + 2
	case 6:
		return uint64(quicvarint.Len(data.ContextID)) + 1 + 16 + 2
	}
	return 0
}

type CompressionClosePayload struct {
	ContextID uint64
}

func (data *CompressionClosePayload) Send(w io.Writer) error {
	bb := quicvarint.Append(make([]byte, 0, 8), data.ContextID)
	_, err := w.Write(bb)
	if err != nil {
		return fmt.Errorf("send context id error: %w", err)
	}
	return nil
}

func (data *CompressionClosePayload) Parse(b []byte) error {
	var err error
	data.ContextID, _, err = quicvarint.Parse(b)
	if err != nil {
		return fmt.Errorf("parse context id error: %v", err)
	}
	return nil
}

func (data *CompressionClosePayload) Len() uint64 {
	return uint64(quicvarint.Len(data.ContextID))
}

type DatagramSender struct {
	sync.Mutex
	w io.Writer
}

func (ds *DatagramSender) SendDatagram(data Datagram) error {
	ds.Lock()
	err := data.Send(ds.w)
	ds.Unlock()
	return err
}

type PacketConn struct {
	DatagramSender
	Conn       net.Conn
	ContextID  uint64
	ContextMap struct {
		sync.RWMutex
		Map map[uint64]netip.AddrPort
	}
	AddrMap struct {
		sync.RWMutex
		Map map[netip.AddrPort]uint64
	}
}

func newPacketConn(conn net.Conn) *PacketConn {
	nm := PacketConn{DatagramSender: DatagramSender{w: conn}, Conn: conn, ContextID: 2}
	nm.ContextMap.Map = map[uint64]netip.AddrPort{}
	nm.AddrMap.Map = map[netip.AddrPort]uint64{}
	return &nm
}

func (nm *PacketConn) GetAddr(id uint64) (netip.AddrPort, bool) {
	nm.ContextMap.RLock()
	addr, ok := nm.ContextMap.Map[id]
	nm.ContextMap.RUnlock()
	return addr, ok
}

func (nm *PacketConn) GetContextID(addr netip.AddrPort) (uint64, bool) {
	nm.AddrMap.RLock()
	id, ok := nm.AddrMap.Map[addr]
	nm.AddrMap.RUnlock()
	return id, ok
}

func (nm *PacketConn) Add(id uint64, addr netip.AddrPort) {
	nm.ContextMap.Lock()
	nm.AddrMap.Lock()
	nm.ContextMap.Map[id] = addr
	nm.AddrMap.Map[addr] = id
	nm.AddrMap.Unlock()
	nm.ContextMap.Unlock()
}

func (nm *PacketConn) Del(id uint64) {
	nm.ContextMap.Lock()
	addr, ok := nm.ContextMap.Map[id]
	delete(nm.ContextMap.Map, id)
	if ok {
		nm.AddrMap.Lock()
		delete(nm.AddrMap.Map, addr)
		nm.AddrMap.Unlock()
	}
	nm.ContextMap.Unlock()
}

func (pc *PacketConn) WriteToUDPAddrPort(b []byte, raddr netip.AddrPort) (int, error) {
	id, ok := pc.GetContextID(raddr)
	if !ok {
		dg := Datagram{
			Type: CompressionAssignValue,
		}
		pl := &CompressionAssignPayload{}
		dg.Payload = pl

		pc.ContextID += 2
		pl.ContextID = pc.ContextID
		if addr := raddr.Addr(); addr.Is4() {
			pl.IPVersion = 4
			pl.Addr = addr
		} else {
			pl.IPVersion = 6
			pl.Addr = addr
		}
		pl.Port = raddr.Port()
		dg.Length = pl.Len()
		dg.Payload = pl

		err := pc.SendDatagram(dg)
		if err != nil {
			return 0, err
		}
	} else {
		dg := Datagram{
			Type: 0,
			Payload: &CompressedPayload{
				ContextID: id,
				Payload:   b,
			},
		}
		dg.Length = uint64(quicvarint.Len(id)) + uint64(len(b))

		err := pc.SendDatagram(dg)
		if err != nil {
			return 0, err
		}

		return len(b), nil
	}

	dg := Datagram{Type: 0}
	pl := UncompressedPayload{
		ContextID: 2,
	}
	if addr := raddr.Addr(); addr.Is4() {
		pl.IPVersion = 4
		pl.Addr = addr
	} else {
		pl.IPVersion = 6
		pl.Addr = addr
	}
	pl.Port = raddr.Port()
	pl.Payload = b
	dg.Length = pl.Len()
	dg.Payload = &pl

	err := pc.SendDatagram(dg)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

type natmap struct {
	sync.RWMutex
	RouteMap map[netip.AddrPort]*PacketConn
}

func newNatMap() *natmap {
	rm := natmap{}
	rm.RouteMap = map[netip.AddrPort]*PacketConn{}
	return &rm
}

func (rm *natmap) Get(addr netip.AddrPort) (*PacketConn, bool) {
	rm.RLock()
	nm, ok := rm.RouteMap[addr]
	rm.RUnlock()
	return nm, ok
}

func (rm *natmap) Add(addr netip.AddrPort, nm *PacketConn) {
	rm.Lock()
	rm.RouteMap[addr] = nm
	rm.Unlock()
}

func (rm *natmap) Del(addr netip.AddrPort) {
	rm.Lock()
	delete(rm.RouteMap, addr)
	rm.Unlock()
}

func (rm *natmap) timedCopy(pc *PacketConn, raddr netip.AddrPort, timeout time.Duration, b []byte) {
	nm := map[netip.AddrPort]*net.UDPConn{}
	mm := map[uint64]*net.UDPConn{}

	dg := Datagram{}
	for {
		pc.Conn.SetReadDeadline(time.Now().Add(timeout))
		err := dg.ReceiveBuffer(pc.Conn, b)
		if err != nil {
			return
		}

		bb := dg.Payload.(*BytePayload).Payload

		switch dg.Type {
		case 0:
			var rc *net.UDPConn
			var pkt []byte
			var addr netip.AddrPort

			id, nr, err := quicvarint.Parse(bb)
			if err != nil {
				return
			}

			if id == 2 {
				switch bb[nr] {
				case 4:
					// nr = 1
					pkt = bb[8:]
					addr = netip.AddrPortFrom(netip.AddrFrom4(
						[4]byte{bb[2], bb[3], bb[4], bb[5]}), uint16(bb[6])<<8|uint16(bb[7]))
				case 6:
					// nr = 1
					pkt = bb[20:]
					addr = netip.AddrPortFrom(netip.AddrFrom16(
						[16]byte{bb[2], bb[3], bb[nr+4], bb[5],
							bb[6], bb[7], bb[8], bb[9],
							bb[10], bb[11], bb[12], bb[13],
							bb[14], bb[15], bb[16], bb[17]}), uint16(bb[18])<<8|uint16(bb[19]))
				default:
					return
				}

				var ok bool
				rc, ok = nm[addr]
				if !ok {
					var err error
					rc, err = tproxy.DialUDP("udp", net.UDPAddrFromAddrPort(addr), net.UDPAddrFromAddrPort(raddr))
					if err != nil {
						return
					}
					defer rc.Close()

					nm[addr] = rc
					if id, ok := pc.GetContextID(addr); ok {
						mm[id] = rc
					}
				}
			} else {
				pkt = bb[nr:]

				var ok bool
				rc, ok = mm[id]
				if !ok {
					addr, ok = pc.GetAddr(id)
					if !ok {
						continue
					} else {
						var err error
						rc, err = tproxy.DialUDP("udp", net.UDPAddrFromAddrPort(addr), net.UDPAddrFromAddrPort(raddr))
						if err != nil {
							return
						}
						defer rc.Close()

						nm[addr] = rc
						mm[id] = rc
					}
				}
			}

			_, err = rc.Write(pkt)
			if err != nil {
				return
			}
		case CompressionAssignValue:
			dg := Datagram{Type: CompressionAssignValue}
			pl := CompressionAssignPayload{}

			err := pl.Parse(bb)
			if err != nil {
				continue
			}
			dg.Length = pl.Len()
			dg.Payload = &pl

			pc.Add(pl.ContextID, netip.AddrPortFrom(pl.Addr, pl.Port))

			if pl.ContextID&1 == 1 {
				err = pc.SendDatagram(dg)
				if err != nil {
					continue
				}
			}
		case CompressionCloseValue:
			dg := Datagram{}
			pl := CompressionClosePayload{}

			err := pl.Parse(bb)
			if err != nil {
				continue
			}
			dg.Length = pl.Len()
			dg.Payload = &pl

			pc.Del(pl.ContextID)

			err = pc.SendDatagram(dg)
			if err != nil {
				continue
			}
			continue
		default:
			continue
		}
	}
}

type Config struct {
	Auth       proxy.Auth
	HostPort   string
	ListenAddr string
	Timeout    time.Duration
	EnableTLS  bool
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
	srv.Dialer = proxy.FromEnvironment()

	host, port, err := net.SplitHostPort(cfg.HostPort)
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
			srv.BasicAuth = "basic " + base64.StdEncoding.EncodeToString([]byte(cfg.Auth.User+":"+cfg.Auth.Password))
		}
	}

	srv.tcpURL = fmt.Sprintf("https://%s", srv.HostPort)
	srv.udpURL = fmt.Sprintf("https://%s/.well-known/masque/udp/*/*/", srv.HostPort)

	srv.ServeTProxy()
	return nil
}

func (srv Server) ServeTProxy() error {
	slog.Info("start tproxy server")

	go srv.ServeTProxyTCP()
	srv.ServeTProxyUDP()

	return nil
}

func (srv Server) ServeTProxyTCP() error {
	addr, err := net.ResolveTCPAddr("tcp", srv.ListenAddr)
	if err != nil {
		return err
	}
	ln, err := tproxy.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	slog.Info(fmt.Sprintf("receive new connnection at %s", ln.Addr().String()))

	for {
		conn, err := ln.AcceptTProxy()
		if err != nil {
			break
		}

		slog.Info(fmt.Sprintf("receive new TCP connection %s <---> %s", conn.RemoteAddr().String(), conn.LocalAddr().String()))

		go func() {
			defer conn.Close()

			rc, err := srv.Dial("tcp", conn.LocalAddr().String())
			if err != nil {
				// slog.Error(fmt.Sprintf("dial TCP connnection to ---> %s, error: %s", conn.LocalAddr().String(), err.Error()))
				return
			}
			defer rc.Close()

			done := make(chan struct{})
			go func() {
				copyBuffer(rc, conn, make([]byte, 1024*16))
				done <- struct{}{}
			}()

			copyBuffer(conn, rc, make([]byte, 1024*16))
			<-done
		}()
	}

	return nil
}

func (srv Server) ServeTProxyUDP() error {
	addr, err := net.ResolveUDPAddr("udp", srv.ListenAddr)
	if err != nil {
		return err
	}
	ln, err := tproxy.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	nm := newNatMap()
	bb := make([]byte, 2048)

	for {
		n, addr, raddr, err := ln.ReadFromUDPAddrPortTProxy(bb)
		if err != nil {
			break
		}

		pc, ok := nm.Get(addr)
		if !ok {
			slog.Info(fmt.Sprintf("receive new UDP connection %s <---> %s", addr.String(), raddr.String()))

			go func(addr, raddr netip.AddrPort, bb []byte, n int) {
				conn, err := srv.Dial("udp", raddr.String())
				if err != nil {
					// slog.Error(fmt.Sprintf("dial UDP connnection to ---> %s, error: %s", raddr.String(), err.Error()))
					return
				}
				defer conn.Close()

				pc = newPacketConn(conn)
				nm.Add(addr, pc)
				defer nm.Del(addr)

				dg := Datagram{
					Type: CompressionAssignValue,
				}
				pl := &CompressionAssignPayload{
					ContextID: 2,
					IPVersion: 0,
				}
				dg.Length = 2
				dg.Payload = pl

				err = pc.SendDatagram(dg)
				if err != nil {
					return
				}

				if _, err := pc.WriteToUDPAddrPort(bb[:n], raddr); err != nil {
					return
				}

				nm.timedCopy(pc, addr, srv.Timeout, bb)
			}(addr, raddr, func() []byte { b := make([]byte, 2048); copy(b, bb[:n]); return b }(), n)

			continue
		}

		if _, err := pc.WriteToUDPAddrPort(bb[:n], raddr); err != nil {
			continue
		}
	}

	return nil
}

func (srv Server) Dial(network, addr string) (net.Conn, error) {
	cc, err := srv.Dialer.Dial("tcp", srv.HostPort)
	if err != nil {
		return nil, err
	}

	conn := func() net.Conn {
		if srv.EnableTLS {
			return net.Conn(tls.Client(cc, &tls.Config{ServerName: srv.Host}))
		}
		return cc
	}()
	switch network {
	case "tcp":
		conn, err = srv.dialTCP(conn, addr)
		if err != nil {
			cc.Close()
			return nil, fmt.Errorf("dial tcp error: %w", err)
		}
		return conn, nil
	case "udp":
		conn, err = srv.dialUDP(conn, addr)
		if err != nil {
			cc.Close()
			return nil, fmt.Errorf("dial udp error: %w", err)
		}
		return conn, nil
	default:
		cc.Close()
		return nil, fmt.Errorf("incorrect network type: %v", network)
	}
}

func (srv Server) dialTCP(conn net.Conn, addr string) (net.Conn, error) {
	req, err := http.NewRequest(http.MethodConnect, srv.tcpURL, nil)
	if err != nil {
		return nil, fmt.Errorf("request error: %w", err)
	}
	req.URL.Opaque = addr
	req.Header.Add("Authorization", srv.BasicAuth)
	req.Header.Add("Proxy-Authorization", srv.BasicAuth)

	err = req.WriteProxy(conn)
	if err != nil {
		return nil, fmt.Errorf("write request error: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, fmt.Errorf("read response error: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server status code error: %v", resp.StatusCode)
	}
	return conn, nil
}

func (srv Server) dialUDP(conn net.Conn, _ string) (net.Conn, error) {
	req, err := http.NewRequest(http.MethodGet, srv.udpURL, nil)
	if err != nil {
		return nil, fmt.Errorf("request error: %w", err)
	}
	req.Header.Add("Connection", "Upgrade")
	req.Header.Add("Upgrade", "connect-udp")
	req.Header.Add("Authorization", srv.BasicAuth)
	req.Header.Add("Proxy-Authorization", srv.BasicAuth)
	req.Header.Add("Connect-Udp-Bind", ConnectUDPBindHeaderValue)

	err = req.WriteProxy(conn)
	if err != nil {
		return nil, fmt.Errorf("write request error: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, fmt.Errorf("read response error: %w", err)
	}
	// slog.Info(fmt.Sprintf("header is %v", resp.Header))
	if str := resp.Header.Get("Connection"); str != "Upgrade" {
		return nil, fmt.Errorf("header Connection error: %v", str)
	}
	if str := resp.Header.Get("Upgrade"); str != "connect-udp" {
		// no Upgrade from server
		// return nil, fmt.Errorf("header Upgrade error: %v", str)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("server status code error: %v", resp.StatusCode)
	}
	return conn, nil
}
