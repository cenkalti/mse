// Package mse (Message Stream Encryption) provides a transparent wrapper for bidirectional
// data streams (e.g. TCP transports) that prevents passive eavesdroping
// and thus protocol or content identification.
//
// It is also designed to provide limited protection against active MITM attacks
// and portscanning by requiring a weak shared secret to complete the handshake.
// You should note that the major design goal was payload and protocol obfuscation,
// not peer authentication and data integrity verification. Thus it does not offer
// protection against adversaries which already know the necessary data to establish
// connections (that is IP/Port/Shared Secret/Payload protocol).
//
// To minimize the load on systems that employ this protocol fast cryptographic
// methods have been chosen over maximum-security algorithms.
package mse

import (
	"io"
)

type Stream struct {
	rw io.ReadWriter
}

func NewStream(rw io.ReadWriter) *Stream {
	return &Stream{rw: rw}
}

func (s *Stream) Read(p []byte) (n int, err error) {
	panic("not implemented")
}

func (s *Stream) Write(p []byte) (n int, err error) {
	panic("not implemented")
}
