package ttproxy

import (
	"net"
	"net/netip"
	"sync"

	"github.com/imgk/ttproxy/pkg/quicvarint"
)

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

func (nm *PacketConn) Close() error {
	return nm.Conn.Close()
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

		id = pl.ContextID
		pc.Add(id, netip.AddrPortFrom(pl.Addr, pl.Port))
	}

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
