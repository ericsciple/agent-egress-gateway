//go:build !linux

package proxy

import (
	"fmt"
	"net"
)

// OriginalDestination is only available where netfilter is. The gateway runs on
// Linux; this exists so the package still builds on a developer's machine.
func OriginalDestination(conn net.Conn) (string, error) {
	return "", fmt.Errorf("SO_ORIGINAL_DST is not available on this platform")
}
