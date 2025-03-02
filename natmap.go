package ttproxy

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/imgk/go-tproxy"
	"github.com/imgk/ttproxy/pkg/quicvarint"
)

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

func (rm *natmap) timedCopy(pc *PacketConn, raddr netip.AddrPort, timeout time.Duration) {
	defer pc.Close()
	defer rm.Del(raddr)

	bb := make([]byte, 2048)
	nm := map[uint64]*net.UDPConn{}

	dg := Datagram{}
	for {
		pc.Conn.SetReadDeadline(time.Now().Add(timeout))
		err := dg.ReceiveBuffer(pc.Conn, bb)
		if err != nil {
			return
		}

		bb := dg.Payload.(*BytePayload).Payload

		switch dg.Type {
		case 0:
			id, nr, err := quicvarint.Parse(bb)
			if err != nil {
				return
			}

			if id == 2 {
				continue
			}

			rc, ok := nm[id]
			if !ok {
				addr, ok := pc.GetAddr(id)
				if !ok {
					continue
				} else {
					slog.Info(fmt.Sprintf("dial new UDP connection %v <---> %v with context id: %v", raddr, addr, id))

					var err error
					rc, err = tproxy.DialUDP("udp", net.UDPAddrFromAddrPort(addr), net.UDPAddrFromAddrPort(raddr))
					if err != nil {
						return
					}
					defer rc.Close()

					nm[id] = rc
				}
			}

			// slog.Info(fmt.Sprintf("write new packet to: %v", raddr))
			_, err = rc.Write(bb[nr:])
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

			if pl.ContextID&1 == 1 {
				// slog.Info(fmt.Sprintf("add new context id: %v, <---> addr: %v", pl.ContextID, netip.AddrPortFrom(pl.Addr, pl.Port)))
				pc.Add(pl.ContextID, netip.AddrPortFrom(pl.Addr, pl.Port))

				err = pc.SendDatagram(dg)
				if err != nil {
					continue
				}
			}
		case CompressionCloseValue:
			dg := Datagram{Type: CompressionCloseValue}
			pl := CompressionClosePayload{}

			err := pl.Parse(bb)
			if err != nil {
				continue
			}
			dg.Length = pl.Len()
			dg.Payload = &pl

			if pl.ContextID&1 == 1 {
				// delete context id
				pc.Del(pl.ContextID)

				err = pc.SendDatagram(dg)
				if err != nil {
					continue
				}
			}
		default:
		}
	}
}
