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
	sync.RWMutex
	Timeout  time.Duration
	RouteMap map[netip.AddrPort]*PacketConn
}

func newNatMap(timeout time.Duration) *natmap {
	rm := natmap{
		Timeout: timeout,
	}
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

	go rm.timedCopy(nm, addr, rm.Timeout)
}

func (rm *natmap) Del(addr netip.AddrPort) {
	rm.Lock()
	delete(rm.RouteMap, addr)
	rm.Unlock()
}

func (rm *natmap) timedCopy(pc *PacketConn, raddr netip.AddrPort, timeout time.Duration) {
	defer pc.Close()
	defer rm.Del(raddr)

	bb := make([]byte, 2048)
	nm := map[uint64]*net.UDPConn{}

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
