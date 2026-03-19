// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var ErrNoValidConnections = errors.New("no valid connections after mtu testing")

const (
	mtuProbeCodeLength  = 4
	mtuProbeRawResponse = 0
	mtuProbeBase64Reply = 1
	EDnsSafeUDPSize     = 4096
	defaultMTUMinFloor  = 30
	defaultUploadMaxCap = 512
)

const mtuProbeFillPattern = "MasterDnsVPN-MTU-Probe-Fill-Pattern-2026"

func (c *Client) RunInitialMTUTests() error {
	if len(c.connections) == 0 {
		return ErrNoValidConnections
	}

	uploadCaps := c.precomputeUploadCaps()
	workerCount := min(max(1, c.cfg.MTUTestParallelism), len(c.connections))
	if workerCount <= 1 {
		for idx := range c.connections {
			c.safeRunConnectionMTUTest(&c.connections[idx], uploadCaps[c.connections[idx].Domain])
		}
	} else {
		jobs := make(chan int, len(c.connections))
		var wg sync.WaitGroup
		for range workerCount {
			wg.Go(func() {
				for idx := range jobs {
					conn := &c.connections[idx]
					c.safeRunConnectionMTUTest(conn, uploadCaps[conn.Domain])
				}
			})
		}
		for idx := range c.connections {
			jobs <- idx
		}
		close(jobs)
		wg.Wait()
	}

	c.balancer.RefreshValidConnections()
	validCount, minUpload, minDownload, minUploadChars := summarizeConnectionMTUStats(c.connections, c)
	if validCount == 0 {
		return ErrNoValidConnections
	}

	c.successMTUChecks = true
	c.syncedUploadMTU = minUpload
	c.syncedDownloadMTU = minDownload
	c.syncedUploadChars = minUploadChars
	c.initResolverRecheckMeta()
	c.updateMaxPackedBlocks()
	return nil
}

func (c *Client) safeRunConnectionMTUTest(conn *Connection, maxUploadPayload int) {
	defer func() {
		if recovered := recover(); recovered != nil {
			conn.IsValid = false
			if c.log != nil {
				c.log.Errorf(
					"💥 <red>MTU Probe Worker Panic Recovered</red> <magenta>|</magenta> <blue>Resolver</blue>: <cyan>%s</cyan> <magenta>|</magenta> <yellow>%v</yellow>",
					conn.ResolverLabel,
					recovered,
				)
			}
		}
	}()
	c.runConnectionMTUTest(conn, maxUploadPayload)
}

func (c *Client) runConnectionMTUTest(conn *Connection, maxUploadPayload int) {
	if !conn.IsValid {
		return
	}

	probeTransport, err := newUDPQueryTransport(conn.ResolverLabel)
	if err != nil {
		conn.IsValid = false
		return
	}
	defer probeTransport.conn.Close()

	upOK, upBytes, err := c.testUploadMTU(conn, probeTransport, maxUploadPayload)
	if err != nil || !upOK {
		conn.IsValid = false
		return
	}

	downOK, downBytes, err := c.testDownloadMTU(conn, probeTransport, upBytes)
	if err != nil || !downOK {
		conn.IsValid = false
		return
	}

	conn.UploadMTUBytes = upBytes
	conn.DownloadMTUBytes = downBytes
}

func (c *Client) precomputeUploadCaps() map[string]int {
	caps := make(map[string]int, len(c.cfg.Domains))
	for _, domain := range c.cfg.Domains {
		if _, exists := caps[domain]; exists {
			continue
		}
		caps[domain] = c.maxUploadMTUPayload(domain)
	}
	return caps
}

func (c *Client) testUploadMTU(conn *Connection, probeTransport *udpQueryTransport, maxPayload int) (bool, int, error) {
	if maxPayload <= 0 {
		return false, 0, nil
	}

	maxLimit := c.cfg.MaxUploadMTU
	if maxLimit <= 0 || maxLimit > defaultUploadMaxCap {
		maxLimit = defaultUploadMaxCap
	}
	if maxPayload > maxLimit {
		maxPayload = maxLimit
	}

	best := c.binarySearchMTU(
		c.cfg.MinUploadMTU,
		maxPayload,
		func(candidate int) (bool, error) {
			return c.sendUploadMTUProbe(conn, probeTransport, candidate)
		},
	)
	if best < max(defaultMTUMinFloor, c.cfg.MinUploadMTU) {
		return false, 0, nil
	}
	return true, best, nil
}

func (c *Client) testDownloadMTU(conn *Connection, probeTransport *udpQueryTransport, uploadMTU int) (bool, int, error) {
	best := c.binarySearchMTU(
		c.cfg.MinDownloadMTU,
		c.cfg.MaxDownloadMTU,
		func(candidate int) (bool, error) {
			return c.sendDownloadMTUProbe(conn, probeTransport, candidate, uploadMTU)
		},
	)
	if best < max(defaultMTUMinFloor, c.cfg.MinDownloadMTU) {
		return false, 0, nil
	}
	return true, best, nil
}

func (c *Client) binarySearchMTU(minValue, maxValue int, testFn func(int) (bool, error)) int {
	if maxValue <= 0 {
		return 0
	}

	low := max(minValue, defaultMTUMinFloor)
	high := maxValue
	if high < low {
		return 0
	}

	check := func(value int) bool {
		ok := false
		for attempt := 0; attempt < c.mtuTestRetries; attempt++ {
			passed, err := testFn(value)
			if err == nil && passed {
				ok = true
				break
			}
		}
		return ok
	}

	if check(high) {
		return high
	}
	if low == high {
		return 0
	}
	if !check(low) {
		return 0
	}

	best := low
	left := low + 1
	right := high - 1
	for left <= right {
		mid := (left + right) / 2
		if check(mid) {
			best = mid
			left = mid + 1
		} else {
			right = mid - 1
		}
	}
	return best
}

func (c *Client) sendUploadMTUProbe(conn *Connection, probeTransport *udpQueryTransport, mtuSize int) (bool, error) {
	if mtuSize < 1+mtuProbeCodeLength {
		return false, nil
	}

	payload, code, useBase64, err := c.buildMTUProbePayload(mtuSize, 0)
	if err != nil {
		return false, err
	}

	query, err := c.buildMTUProbeQuery(conn.Domain, Enums.PACKET_MTU_UP_REQ, payload)
	if err != nil {
		return false, nil
	}

	response, err := exchangeUDPQuery(probeTransport, query, c.mtuTestTimeout)
	if err != nil {
		return false, nil
	}

	packet, err := DnsParser.ExtractVPNResponse(response, useBase64)
	if err != nil {
		return false, nil
	}
	if !c.validateServerPacket(packet) {
		return false, nil
	}
	if packet.PacketType != Enums.PACKET_MTU_UP_RES {
		return false, nil
	}
	if len(packet.Payload) != 6 {
		return false, nil
	}
	if !bytes.Equal(packet.Payload[:mtuProbeCodeLength], code) {
		return false, nil
	}
	return int(binary.BigEndian.Uint16(packet.Payload[mtuProbeCodeLength:mtuProbeCodeLength+2])) == mtuSize, nil
}

func (c *Client) sendDownloadMTUProbe(conn *Connection, probeTransport *udpQueryTransport, mtuSize int, uploadMTU int) (bool, error) {
	if mtuSize < defaultMTUMinFloor {
		return false, nil
	}

	requestLen := max(1+mtuProbeCodeLength+2, uploadMTU)
	payload, code, useBase64, err := c.buildMTUProbePayload(requestLen, 2)
	if err != nil {
		return false, err
	}
	binary.BigEndian.PutUint16(payload[1+mtuProbeCodeLength:1+mtuProbeCodeLength+2], uint16(mtuSize))

	query, err := c.buildMTUProbeQuery(conn.Domain, Enums.PACKET_MTU_DOWN_REQ, payload)
	if err != nil {
		return false, nil
	}

	response, err := exchangeUDPQuery(probeTransport, query, c.mtuTestTimeout)
	if err != nil {
		return false, nil
	}

	packet, err := DnsParser.ExtractVPNResponse(response, useBase64)
	if err != nil {
		return false, nil
	}
	if !c.validateServerPacket(packet) {
		return false, nil
	}
	if packet.PacketType != Enums.PACKET_MTU_DOWN_RES {
		return false, nil
	}
	if len(packet.Payload) != mtuSize {
		return false, nil
	}
	if len(packet.Payload) < 1+mtuProbeCodeLength+1 {
		return false, nil
	}
	if !bytes.Equal(packet.Payload[:mtuProbeCodeLength], code) {
		return false, nil
	}
	return int(binary.BigEndian.Uint16(packet.Payload[mtuProbeCodeLength:mtuProbeCodeLength+2])) == mtuSize, nil
}

func (c *Client) buildMTUProbeQuery(domain string, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelTXTQueryRaw(domain, VpnProto.BuildOptions{
		SessionID:      255,
		PacketType:     packetType,
		StreamID:       1,
		SequenceNum:    1,
		FragmentID:     0,
		TotalFragments: 1,
		Payload:        payload,
	})
}

func (c *Client) maxUploadMTUPayload(domain string) int {
	maxChars := DnsParser.CalculateMaxEncodedQNameChars(domain)
	if maxChars <= 0 {
		return 0
	}

	low := 0
	high := maxChars
	best := 0
	for low <= high {
		mid := (low + high) / 2
		if c.canBuildUploadPayload(domain, mid) {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}
	return best
}

func (c *Client) canBuildUploadPayload(domain string, payloadLen int) bool {
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = 0xAB
	}
	packetType := VpnProto.MaxHeaderPacketType()
	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID:       255,
		PacketType:      packetType,
		SessionCookie:   255,
		StreamID:        0xFFFF,
		SequenceNum:     0xFFFF,
		FragmentID:      0xFF,
		TotalFragments:  0xFF,
		CompressionType: 0xFF,
		Payload:         payload,
	}, c.codec)
	if err != nil {
		return false
	}

	_, err = DnsParser.BuildTunnelQuestionName(domain, encoded)
	return err == nil
}

func (c *Client) buildMTUProbePayload(length int, reservedTailPrefix int) ([]byte, []byte, bool, error) {
	if length <= 0 {
		return nil, nil, false, nil
	}

	payload := make([]byte, length)
	useBase64 := c != nil && c.cfg.BaseEncodeData
	payload[0] = mtuProbeRawResponse
	if useBase64 {
		payload[0] = mtuProbeBase64Reply
	}

	code, err := randomBytes(mtuProbeCodeLength)
	if err != nil {
		return nil, nil, false, err
	}
	copy(payload[1:1+mtuProbeCodeLength], code)

	fillOffset := 1 + mtuProbeCodeLength + reservedTailPrefix
	if fillOffset < len(payload) {
		fillMTUProbeBytes(payload[fillOffset:])
	}

	return payload, code, useBase64, nil
}

func fillMTUProbeBytes(dst []byte) {
	if len(dst) == 0 {
		return
	}
	pattern := mtuProbeFillPattern
	offset := 0
	for offset < len(dst) {
		offset += copy(dst[offset:], pattern)
	}
}

func randomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return []byte{}, nil
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func summarizeConnectionMTUStats(connections []Connection, c *Client) (validCount int, minUpload int, minDownload int, minUploadChars int) {
	for _, conn := range connections {
		if !conn.IsValid {
			continue
		}
		validCount++

		if conn.UploadMTUBytes > 0 && (minUpload == 0 || conn.UploadMTUBytes < minUpload) {
			minUpload = conn.UploadMTUBytes
		}
		if conn.DownloadMTUBytes > 0 && (minDownload == 0 || conn.DownloadMTUBytes < minDownload) {
			minDownload = conn.DownloadMTUBytes
		}
		if conn.UploadMTUBytes <= 0 || c == nil {
			continue
		}
		value := c.encodedCharsForPayload(conn.UploadMTUBytes)
		if value > 0 && (minUploadChars == 0 || value < minUploadChars) {
			minUploadChars = value
		}
	}
	return validCount, minUpload, minDownload, minUploadChars
}

func (c *Client) encodedCharsForPayload(payloadLen int) int {
	if payloadLen <= 0 {
		return 0
	}
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = 0xAB
	}
	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID:       255,
		PacketType:      Enums.PACKET_STREAM_DATA,
		SessionCookie:   255,
		StreamID:        0xFFFF,
		SequenceNum:     0xFFFF,
		FragmentID:      0xFF,
		TotalFragments:  0xFF,
		CompressionType: 0xFF,
		Payload:         payload,
	}, c.codec)
	if err != nil {
		return 0
	}
	return len(encoded)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
