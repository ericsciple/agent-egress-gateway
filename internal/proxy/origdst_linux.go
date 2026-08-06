//go:build linux

package proxy

import (
	"fmt"
	"net"
	"syscall"
)

// soOriginalDst is SO_ORIGINAL_DST from linux/netfilter.h.
const soOriginalDst = 80

// OriginalDestination recovers the address a connection was headed for before
// netfilter redirected it.
//
// This is only a logging and diagnostic aid. It is never used to select a lane or
// an upstream: in the sandbox topology the redirect rule lives inside the guest,
// where a root process can point it anywhere it likes.
func OriginalDestination(conn net.Conn) (string, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a TCP connection")
	}
	f, err := tcp.File()
	if err != nil {
		return "", fmt.Errorf("obtaining fd: %w", err)
	}
	defer f.Close()

	addr, err := syscall.GetsockoptIPv6Mreq(int(f.Fd()), syscall.IPPROTO_IP, soOriginalDst)
	if err != nil {
		return "", fmt.Errorf("getsockopt SO_ORIGINAL_DST: %w", err)
	}

	ip := net.IPv4(addr.Multiaddr[4], addr.Multiaddr[5], addr.Multiaddr[6], addr.Multiaddr[7])
	port := int(addr.Multiaddr[2])<<8 | int(addr.Multiaddr[3])
	return net.JoinHostPort(ip.String(), fmt.Sprint(port)), nil
}
