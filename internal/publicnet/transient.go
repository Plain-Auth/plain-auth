package publicnet

import (
	"errors"
	"io"
	"net"
	"syscall"
)

// Transient reports a network failure that may pass on retry, as another
// runtime reads Node error codes: a temporary or timed-out DNS answer, a
// connection reset, refused, timed out or unreachable, a broken pipe, a
// timeout, or a connection closed mid-response. A TLS failure, a missing
// host and other local errors are not transient.
func Transient(err error) bool {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return dns.IsTemporary || dns.IsTimeout
	}
	for _, errno := range []syscall.Errno{syscall.ECONNRESET, syscall.ECONNREFUSED, syscall.ETIMEDOUT, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EPIPE} {
		if errors.Is(err, errno) {
			return true
		}
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout() || errors.Is(err, io.ErrUnexpectedEOF)
}
