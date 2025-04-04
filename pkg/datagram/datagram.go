package datagram

import (
	"fmt"
	"io"
	"net/netip"
	"sync"

	"github.com/imgk/ttproxy/pkg/quicvarint"
)

type Payload interface {
	Append([]byte) []byte
	Len() uint64
	Parse([]byte) error
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

func (data *Datagram) Append(b []byte) []byte {
	b = quicvarint.Append(quicvarint.Append(b, data.Type), data.Length)
	return data.Payload.Append(b)
}

type BytePayload struct {
	Payload []byte
}

func (data *BytePayload) Send(w io.Writer) error {
	_, err := w.Write(data.Payload)
	return err
}

func (data *BytePayload) Len() uint64 {
	return uint64(len(data.Payload))
}

func (data *BytePayload) Parse(b []byte) error {
	data.Payload = b
	return nil
}

func (data *BytePayload) Append(b []byte) []byte {
	return append(b, data.Payload...)
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

func (data *CompressedPayload) Append(b []byte) []byte {
	return append(quicvarint.Append(b, data.ContextID), data.Payload...)
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

func (data *UncompressedPayload) Append(b []byte) []byte {
	return append(append(append(append(quicvarint.Append(b, data.ContextID), byte(data.IPVersion)),
		data.Addr.AsSlice()...), byte(data.Port>>8), byte(data.Port)), data.Payload...)
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

func (data *CompressionAssignPayload) Append(b []byte) []byte {
	if data.IPVersion != 0 {
		return append(append(append(quicvarint.Append(b, data.ContextID),
			byte(data.IPVersion)), data.Addr.AsSlice()...), byte(data.Port>>8), byte(data.Port))
	}

	return append(quicvarint.Append(b, data.ContextID), byte(data.IPVersion))
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

func (data *CompressionClosePayload) Append(b []byte) []byte {
	return quicvarint.Append(b, data.ContextID)
}

type DatagramSender struct {
	sync.Mutex
	W io.Writer
}

func (ds *DatagramSender) SendDatagram(data Datagram) error {
	ds.Lock()
	err := data.Send(ds.W)
	ds.Unlock()
	return err
}

var (
	_ Payload = (*BytePayload)(nil)
	_ Payload = (*CompressedPayload)(nil)
	_ Payload = (*UncompressedPayload)(nil)
	_ Payload = (*CompressionAssignPayload)(nil)
	_ Payload = (*CompressionClosePayload)(nil)
)
