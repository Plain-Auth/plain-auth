package publicnet

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"syscall"
	"testing"
)

type timeout struct{}

func (timeout) Error() string   { return "timeout" }
func (timeout) Timeout() bool   { return true }
func (timeout) Temporary() bool { return true }

func TestTransient(t *testing.T) {
	dial := func(errno syscall.Errno) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
	}
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"reset": {dial(syscall.ECONNRESET), true}, "refused": {dial(syscall.ECONNREFUSED), true}, "timed out": {dial(syscall.ETIMEDOUT), true},
		"host": {dial(syscall.EHOSTUNREACH), true}, "network": {dial(syscall.ENETUNREACH), true}, "pipe": {fmt.Errorf("write: %w", syscall.EPIPE), true},
		"dns temporary": {&net.DNSError{Err: "server misbehaving", IsTemporary: true}, true}, "dns timeout": {&net.DNSError{Err: "i/o timeout", IsTimeout: true}, true},
		"dns not found": {&net.DNSError{Err: "no such host", IsNotFound: true}, false}, "timeout": {timeout{}, true}, "eof": {io.ErrUnexpectedEOF, true},
		"closed": {&url.Error{Op: "Get", URL: "https://example.com", Err: io.EOF}, true},
		"tls":    {&net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}, false}, "files": {dial(syscall.EMFILE), false}, "other": {errors.New("x"), false},
	} {
		if got := Transient(tc.err); got != tc.want {
			t.Error("wrong transient answer", name, got)
		}
	}
}
