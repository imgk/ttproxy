package ttproxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/imgk/go-tproxy"
)

func (srv Server) ServeTProxyTCP() error {
	addr, err := net.ResolveTCPAddr("tcp", srv.TProxyAddr)
	if err != nil {
		return err
	}
	ln, err := tproxy.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	slog.Info(fmt.Sprintf("receive new tproxy connnection at %s", ln.Addr().String()))

	for {
		conn, err := ln.AcceptTProxy()
		if err != nil {
			break
		}

		slog.Info(fmt.Sprintf("receive new tproxy TCP connection %s <---> %s", conn.RemoteAddr().String(), conn.LocalAddr().String()))

		go srv.relay(conn)
	}

	return nil
}

func (srv Server) relay(conn tproxy.Conn) {
	defer conn.Close()

	rc, err := srv.Dial("tcp", conn.LocalAddr().String())
	if err != nil {
		// slog.Error(fmt.Sprintf("dial TCP connnection to ---> %s, error: %s", conn.LocalAddr().String(), err.Error()))
		return
	}
	defer rc.Close()

	done := make(chan struct{})
	go func() {
		io.Copy(rc, conn)
		// conn.WriteTo(rc)
		// copyBuffer(rc, conn, make([]byte, 1024*16))
		if cw, ok := rc.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()

	io.Copy(conn, rc)
	// conn.ReadFrom(rc)
	// copyBuffer(conn, rc, make([]byte, 1024*16))
	conn.CloseWrite()
	<-done
}

func (srv Server) ServeTProxyUDP() error {
	addr, err := net.ResolveUDPAddr("udp", srv.TProxyAddr)
	if err != nil {
		return err
	}
	ln, err := tproxy.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	nm := newNatMap(srv.Timeout)
	bb := make([]byte, 2048)

	for {
		n, addr, raddr, err := ln.ReadFromUDPAddrPortTProxy(bb)
		if err != nil {
			break
		}

		pc, ok := nm.Get(addr)
		if ok {
			// write packet to remote connection if found
			if _, err := pc.WriteToUDPAddrPort(bb[:n], raddr); err != nil {
				slog.Error(fmt.Sprintf("write from: %v to: %v error: %v", addr, raddr, err))
			}
			continue
		}

		// create new connection for new address
		slog.Info(fmt.Sprintf("receive new tproxy UDP connection %s <---> %s", addr.String(), raddr.String()))

		conn, err := srv.Dial("udp", raddr.String())
		if err != nil {
			// slog.Error(fmt.Sprintf("dial UDP connnection to ---> %s, error: %s", raddr.String(), err.Error()))
			continue
		}

		pc = newPacketConn(conn)
		// enable firewall for default
		// only transport packets with context id
		err = pc.SetFirewall(true)
		if err != nil {
			pc.Close()
			continue
		}

		_, err = pc.WriteToUDPAddrPort(bb[:n], raddr)
		if err != nil {
			pc.Close()
			continue
		}

		nm.Add(addr, pc)
	}

	return nil
}
