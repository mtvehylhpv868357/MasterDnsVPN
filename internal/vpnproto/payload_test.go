// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"bytes"
	"testing"

	"masterdnsvpn-go/internal/compression"
	ENUMS "masterdnsvpn-go/internal/enums"
)

func TestPreparePayloadCompressesSupportedPacket(t *testing.T) {
	payload := bytes.Repeat([]byte("abcdabcdabcdabcd"), 16)
	compressed, used := PreparePayload(ENUMS.PacketStreamData, payload, compression.TypeZLIB, compression.DefaultMinSize)
	if used != compression.TypeZLIB {
		t.Fatalf("unexpected compression type: got=%d want=%d", used, compression.TypeZLIB)
	}
	if len(compressed) >= len(payload) {
		t.Fatalf("expected compressed payload to be smaller: got=%d raw=%d", len(compressed), len(payload))
	}
}

func TestPreparePayloadSkipsUnsupportedPacket(t *testing.T) {
	payload := bytes.Repeat([]byte("abcdabcdabcdabcd"), 16)
	compressed, used := PreparePayload(ENUMS.PacketSessionInit, payload, compression.TypeZLIB, compression.DefaultMinSize)
	if used != compression.TypeOff {
		t.Fatalf("unexpected compression type: got=%d want=%d", used, compression.TypeOff)
	}
	if !bytes.Equal(compressed, payload) {
		t.Fatal("session init payload must not be compressed")
	}
}

func TestInflatePayloadRoundTrip(t *testing.T) {
	rawPayload := bytes.Repeat([]byte("abcdabcdabcdabcd"), 16)
	compressed, used := PreparePayload(ENUMS.PacketStreamData, rawPayload, compression.TypeZLIB, compression.DefaultMinSize)
	packet := Packet{
		PacketType:         ENUMS.PacketStreamData,
		HasCompressionType: true,
		CompressionType:    used,
		Payload:            compressed,
	}

	inflated, err := InflatePayload(packet)
	if err != nil {
		t.Fatalf("InflatePayload returned error: %v", err)
	}
	if !bytes.Equal(inflated.Payload, rawPayload) {
		t.Fatal("inflated payload mismatch")
	}
}
