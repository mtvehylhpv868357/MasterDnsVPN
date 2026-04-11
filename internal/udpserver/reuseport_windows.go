//go:build windows

package udpserver

import (
	"errors"
	"net"
)

var errReusePortUnsupported = errors.New("reuseport unsupported")

func listenUDPReusePort(addr *net.UDPAddr) (*net.UDPConn, error) {
	return nil, errReusePortUnsupported
}
