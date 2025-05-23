package ttproxy

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/imgk/ttproxy/pkg/datagram"
	"github.com/imgk/ttproxy/pkg/quicvarint"
)

type PacketConn struct {
	datagram.DatagramSender
	Conn       net.Conn
	ContextID  uint64
	ContextMap sync.Map
	AddrMap    sync.Map

	firewall atomic.Bool
}

func newPacketConn(conn net.Conn) *PacketConn {
	pc := PacketConn{DatagramSender: datagram.DatagramSender{W: conn}, Conn: conn, ContextID: 2}
	return &pc
}

func (nm *PacketConn) Close() error {
	return nm.Conn.Close()
}

func (nm *PacketConn) SetFirewall(ok bool) error {
	if ok {
		// enable firewall for UDP bind
		dg := datagram.Datagram{
			Type: CompressionCloseValue,
		}
		pl := &datagram.CompressionClosePayload{
			ContextID: 2,
		}
		dg.Length = 1
		dg.Payload = pl

		err := nm.SendDatagram(dg)
		if err != nil {
			return err
		}
	} else {
		// disable firewall for UDP bind
		dg := datagram.Datagram{
			Type: CompressionAssignValue,
		}
		pl := &datagram.CompressionAssignPayload{
			ContextID: 2,
			IPVersion: 0,
		}
		dg.Length = 2
		dg.Payload = pl

		err := nm.SendDatagram(dg)
		if err != nil {
			return err
		}
	}

	nm.firewall.Store(ok)
	return nil
}

func (nm *PacketConn) Firewall() bool {
	return nm.firewall.Load()
}

func (nm *PacketConn) GetAddr(id uint64) (netip.AddrPort, bool) {
	addr, ok := nm.ContextMap.Load(id)
	if ok {
		return addr.(netip.AddrPort), true
	}
	return netip.AddrPort{}, ok
}

func (nm *PacketConn) GetContextID(addr netip.AddrPort) (uint64, bool) {
	id, ok := nm.AddrMap.Load(addr)
	if ok {
		return id.(uint64), true
	}
	return 0, ok
}

func (nm *PacketConn) Add(id uint64, addr netip.AddrPort) {
	nm.ContextMap.Store(id, addr)
	nm.AddrMap.Store(addr, id)
}

func (nm *PacketConn) Del(id uint64) {
	addr, ok := nm.ContextMap.LoadAndDelete(id)
	if ok {
		nm.AddrMap.Delete(addr)
	}
}

func (pc *PacketConn) WriteToUDPAddrPort(b []byte, raddr netip.AddrPort) (int, error) {
	id, ok := pc.GetContextID(raddr)
	if !ok {
		dg := datagram.Datagram{
			Type: CompressionAssignValue,
		}
		pl := &datagram.CompressionAssignPayload{}

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

	dg := datagram.Datagram{
		Type: 0,
		Payload: &datagram.CompressedPayload{
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

func (pc *PacketConn) ReadPacket(buf []byte) ([]byte, uint64, error) {
	for {
		dg := datagram.Datagram{}
		err := dg.ReceiveBuffer(pc.Conn, buf)
		if err != nil {
			return nil, 0, err
		}

		bb := dg.Payload.(*datagram.BytePayload).Payload

		switch dg.Type {
		case 0:
			id, nr, err := quicvarint.Parse(bb)
			if err != nil {
				continue
			}

			// use 1 for server side
			// use 2 for client side
			if id != 1 {
				return bb[nr:], id, nil
			}

			if pc.Firewall() {
				continue
			}

			var (
				pkt  []byte
				addr netip.AddrPort
			)
			switch bb[1] {
			case 4:
				// nr = 1
				pkt = bb[8:]
				addr = netip.AddrPortFrom(netip.AddrFrom4(
					[4]byte{bb[2], bb[3], bb[4], bb[5]}), uint16(bb[6])<<8|uint16(bb[7]))
			case 6:
				// nr = 1
				pkt = bb[20:]
				addr = netip.AddrPortFrom(netip.AddrFrom16(
					[16]byte{bb[2], bb[3], bb[4], bb[5],
						bb[6], bb[7], bb[8], bb[9],
						bb[10], bb[11], bb[12], bb[13],
						bb[14], bb[15], bb[16], bb[17]}), uint16(bb[18])<<8|uint16(bb[19]))
			default:
				continue
			}

			id, ok := pc.GetContextID(addr)
			if ok {
				return pkt, id, nil
			}

			dg := datagram.Datagram{
				Type: CompressionAssignValue,
			}
			pl := &datagram.CompressionAssignPayload{}

			pc.ContextID += 2
			pl.ContextID = pc.ContextID
			if naddr := addr.Addr(); naddr.Is4() {
				pl.IPVersion = 4
				pl.Addr = naddr
			} else {
				pl.IPVersion = 6
				pl.Addr = naddr
			}
			pl.Port = addr.Port()
			dg.Length = pl.Len()
			dg.Payload = pl

			err = pc.SendDatagram(dg)
			if err != nil {
				return nil, 0, err
			}

			id = pl.ContextID
			pc.Add(id, netip.AddrPortFrom(pl.Addr, pl.Port))

			return pkt, id, nil
		case CompressionAssignValue:
			dg := datagram.Datagram{Type: CompressionAssignValue}
			pl := datagram.CompressionAssignPayload{}

			err := pl.Parse(bb)
			if err != nil {
				continue
			}
			dg.Length = pl.Len()
			dg.Payload = &pl

			// odd context id for server side
			if pl.ContextID&1 == 1 {
				// slog.Info(fmt.Sprintf("add new context id: %v, <---> addr: %v", pl.ContextID, netip.AddrPortFrom(pl.Addr, pl.Port)))
				pc.Add(pl.ContextID, netip.AddrPortFrom(pl.Addr, pl.Port))

				err = pc.SendDatagram(dg)
				if err != nil {
					continue
				}
			}
		case CompressionCloseValue:
			dg := datagram.Datagram{Type: CompressionCloseValue}
			pl := datagram.CompressionClosePayload{}

			err := pl.Parse(bb)
			if err != nil {
				continue
			}
			dg.Length = pl.Len()
			dg.Payload = &pl

			// odd context id for server side
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
