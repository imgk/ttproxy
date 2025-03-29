package ttproxy

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/imgk/go-tproxy"
)

type natmap struct {
	Timeout  time.Duration
	RouteMap sync.Map
}

func newNatMap(timeout time.Duration) *natmap {
	rm := natmap{
		Timeout: timeout,
	}
	return &rm
}

func (rm *natmap) Get(addr netip.AddrPort) (*PacketConn, bool) {
	v, ok := rm.RouteMap.Load(addr)
	if ok {
		return v.(*PacketConn), true
	}
	return nil, ok
}

func (rm *natmap) Add(addr netip.AddrPort, pc *PacketConn) {
	rm.RouteMap.Store(addr, pc)

	go func() {
		rm.timedCopy(pc, addr, rm.Timeout)
		rm.RouteMap.Delete(addr)
	}()
}

func (rm *natmap) Del(addr netip.AddrPort) {
	rm.RouteMap.Delete(addr)
}

func (rm *natmap) timedCopy(pc *PacketConn, raddr netip.AddrPort, timeout time.Duration) {
	defer pc.Close()

	bb := make([]byte, 2048)
	nm := map[uint64]tproxy.PacketConn{}

	for {
		pc.SetReadDeadline(time.Now().Add(timeout))
		pkt, id, err := pc.ReadPacket(bb)
		if err != nil {
			break
		}

		rc, ok := nm[id]
		if !ok {
			addr, ok := pc.GetAddr(id)
			if !ok {
				continue
			}

			slog.Info(fmt.Sprintf("dial new UDP connection %v <---> %v with context id: %v", raddr, addr, id))

			var err error
			rc, err = tproxy.DialUDP("udp", net.UDPAddrFromAddrPort(addr), net.UDPAddrFromAddrPort(raddr))
			if err != nil {
				return
			}
			defer rc.Close()

			nm[id] = rc
		}

		// slog.Info(fmt.Sprintf("write new packet to: %v", raddr))
		_, err = rc.Write(pkt)
		if err != nil {
			return
		}
	}
}
