// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"sync"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

type streamOutboundStore struct {
	mu       sync.Mutex
	sessions map[uint8]*streamOutboundSession
}

type streamOutboundSession struct {
	queue   []VpnProto.Packet
	pending *VpnProto.Packet
}

func newStreamOutboundStore() *streamOutboundStore {
	return &streamOutboundStore{
		sessions: make(map[uint8]*streamOutboundSession, 32),
	}
}

func (s *streamOutboundStore) Enqueue(sessionID uint8, packet VpnProto.Packet) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil {
		session = &streamOutboundSession{
			queue: make([]VpnProto.Packet, 0, 8),
		}
		s.sessions[sessionID] = session
	}
	packet.Payload = append([]byte(nil), packet.Payload...)
	session.queue = append(session.queue, packet)
}

func (s *streamOutboundStore) Next(sessionID uint8) (VpnProto.Packet, bool) {
	if s == nil {
		return VpnProto.Packet{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil {
		return VpnProto.Packet{}, false
	}
	if session.pending != nil {
		packet := *session.pending
		packet.Payload = append([]byte(nil), packet.Payload...)
		return packet, true
	}
	if len(session.queue) == 0 {
		return VpnProto.Packet{}, false
	}

	packet := session.queue[0]
	session.queue[0] = VpnProto.Packet{}
	session.queue = session.queue[1:]
	session.pending = &packet
	packet.Payload = append([]byte(nil), packet.Payload...)
	return packet, true
}

func (s *streamOutboundStore) Ack(sessionID uint8, packetType uint8, streamID uint16, sequenceNum uint16) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil || session.pending == nil {
		return false
	}
	if !matchesStreamOutboundAck(session.pending.PacketType, packetType) {
		return false
	}
	if session.pending.StreamID != streamID || session.pending.SequenceNum != sequenceNum {
		return false
	}

	session.pending = nil
	if len(session.queue) == 0 {
		delete(s.sessions, sessionID)
	}
	return true
}

func (s *streamOutboundStore) ClearStream(sessionID uint8, streamID uint16) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.sessions[sessionID]
	if session == nil {
		return
	}
	if session.pending != nil && session.pending.StreamID == streamID {
		session.pending = nil
	}
	if len(session.queue) != 0 {
		filtered := session.queue[:0]
		for _, packet := range session.queue {
			if packet.StreamID != streamID {
				filtered = append(filtered, packet)
			}
		}
		session.queue = filtered
	}
	if session.pending == nil && len(session.queue) == 0 {
		delete(s.sessions, sessionID)
	}
}

func (s *streamOutboundStore) RemoveSession(sessionID uint8) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.mu.Unlock()
}

func matchesStreamOutboundAck(pendingType uint8, ackType uint8) bool {
	switch pendingType {
	case Enums.PACKET_STREAM_DATA:
		return ackType == Enums.PACKET_STREAM_DATA_ACK
	case Enums.PACKET_STREAM_FIN:
		return ackType == Enums.PACKET_STREAM_FIN_ACK
	case Enums.PACKET_STREAM_RST:
		return ackType == Enums.PACKET_STREAM_RST_ACK
	default:
		return false
	}
}
