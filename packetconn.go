package ttproxy

import (
	"net"
	"net/netip"
	"sync"
	"time"

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

func (pc *PacketConn) SetReadDeadline(time time.Time) error {
	return pc.Conn.SetReadDeadline(time)
}

func (pc *PacketConn) ReadPacket(buf []byte) (int, uint64, error) {
	for {
		dg := Datagram{}
		err := dg.ReceiveBuffer(pc.Conn, buf)
		if err != nil {
			return 0, 0, err
		}

		bb := dg.Payload.(*BytePayload).Payload

		switch dg.Type {
		case 0:
			id, nr, err := quicvarint.Parse(bb)
			if err != nil {
				return 0, 0, err
			}

			if id == 2 {
				continue
			}

			return nr, id, nil
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
