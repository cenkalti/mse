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
//
// See http://wiki.vuze.com/w/Message_Stream_Encryption for details.
package mse

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"net"
	"time"
)

const connDeadline = 30 * time.Second

const enableDebug = false

func debugln(args ...interface{}) {
	if enableDebug {
		fmt.Println(args...)
	}
}

func debugf(format string, args ...interface{}) {
	if enableDebug {
		fmt.Printf(format, args...)
	}
}

var (
	pBytes = []byte{255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198, 98, 139, 128, 220, 28, 209, 41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34, 81, 74, 8, 121, 142, 52, 4, 221, 239, 149, 25, 179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79, 225, 53, 109, 109, 81, 194, 69, 228, 133, 181, 118, 98, 94, 126, 198, 244, 76, 66, 233, 166, 58, 54, 33, 0, 0, 0, 0, 0, 9, 5, 99}
	p      = new(big.Int)
	g      = big.NewInt(2)
	vc     = make([]byte, 8)
)

func init() { p.SetBytes(pBytes) }

// CryptoMethod is 32-bit bitfield each bit representing a single crypto method.
type CryptoMethod uint32

// Crypto methods
const (
	PlainText CryptoMethod = 1 << iota
	RC4
)

func (c CryptoMethod) String() string {
	switch c {
	case PlainText:
		return "PlainText"
	case RC4:
		return "RC4"
	default:
		return "unknown"
	}
}

// Stream wraps a io.ReadWriter that automatically does encrypt/decrypt on read/write.
type Stream struct {
	raw io.ReadWriter
	r   *cipher.StreamReader
	w   *cipher.StreamWriter
}

// NewStream returns a new Stream. You must call HandshakeIncoming or
// HandshakeOutgoing methods before using Read/Write methods.
// If any error happens during the handshake underlying io.ReadWriter will be closed if it implements io.Closer.
// If underlying io.ReadWriter implements net.Conn interface, read and write deadlines will be reset after the handshake, so if you are setting deadlines do it after the handshake.
func NewStream(rw io.ReadWriter) *Stream { return &Stream{raw: rw} }

// Read from underlying io.ReadWriter, decrypt bytes and put into p.
func (s *Stream) Read(p []byte) (n int, err error) { return s.r.Read(p) }

// Encrypt bytes in p and write into underlying io.ReadWriter.
func (s *Stream) Write(p []byte) (n int, err error) { return s.w.Write(p) }

// HandshakeOutgoing initiates MSE handshake for outgoing connection.
//
// sKey is stream identifier key. Same key must be used at the other side of the stream, otherwise handshake fails.
//
// cryptoProvide is a bitfield for specifying supported encryption methods.
//
// payload is initial payload that is going to be sent along with handshake.
// It may be nil if you want to wait for the encryption negotation.
func (s *Stream) HandshakeOutgoing(sKey []byte, cryptoProvide CryptoMethod, payload []byte) (selected CryptoMethod, err error) {

	defer func() {
		if err != nil {
			if c, ok := s.raw.(io.Closer); ok {
				c.Close()
			}
		}
	}()

	if cryptoProvide == 0 {
		err = errors.New("no crypto methods are provided")
		return
	}
	if len(payload) > math.MaxUint16 {
		err = errors.New("initial payload is too big")
		return
	}

	writeBuf := bytes.NewBuffer(make([]byte, 0, 96+512))

	Xa, Ya, err := keyPair()
	if err != nil {
		return
	}

	// Step 1 | A->B: Diffie Hellman Ya, PadA
	if conn, ok := s.raw.(net.Conn); ok {
		if err = conn.SetWriteDeadline(time.Now().Add(connDeadline)); err != nil {
			return
		}
	}
	writeBuf.Write(bytesWithPad(Ya))
	padA, err := padRandom()
	if err != nil {
		return
	}
	writeBuf.Write(padA)
	debugln("--- out: writing Step 1")
	_, err = writeBuf.WriteTo(s.raw)
	if err != nil {
		return
	}
	debugln("--- out: done")

	// Step 2 | B->A: Diffie Hellman Yb, PadB
	if conn, ok := s.raw.(net.Conn); ok {
		if err = conn.SetReadDeadline(time.Now().Add(connDeadline)); err != nil {
			return
		}
	}
	b := make([]byte, 96+512)
	debugln("--- out: reading PubkeyB")
	firstRead, err := io.ReadAtLeast(s.raw, b, 96)
	debugln("--- out: done")
	debugf("--- out: firstRead: %d\n", firstRead)
	if err != nil {
		return
	}
	Yb := new(big.Int)
	Yb.SetBytes(b[:96])
	S := Yb.Exp(Yb, Xa, p)
	err = s.initRC4("keyA", "keyB", S, sKey)
	if err != nil {
		return
	}

	// Step 3 | A->B: HASH('req1', S), HASH('req2', SKEY) xor HASH('req3', S), ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA)), ENCRYPT(IA)
	if conn, ok := s.raw.(net.Conn); ok {
		if err = conn.SetWriteDeadline(time.Now().Add(connDeadline)); err != nil {
			return
		}
	}
	hashS, hashSKey := hashes(S, sKey)
	padC, err := padZero()
	if err != nil {
		return
	}
	writeBuf.Write(hashS)
	writeBuf.Write(hashSKey)
	writeBuf.Write(vc)
	binary.Write(writeBuf, binary.BigEndian, cryptoProvide)
	binary.Write(writeBuf, binary.BigEndian, uint16(len(padC)))
	writeBuf.Write(padC)
	binary.Write(writeBuf, binary.BigEndian, uint16(len(payload)))
	writeBuf.Write(payload)
	encBytes := writeBuf.Bytes()[40:]
	s.w.S.XORKeyStream(encBytes, encBytes) // RC4
	debugln("--- out: writing Step 3")
	_, err = writeBuf.WriteTo(s.raw)
	if err != nil {
		return
	}
	debugln("--- out: done")

	// Step 4 | B->A: ENCRYPT(VC, crypto_select, len(padD), padD), ENCRYPT2(Payload Stream)
	if conn, ok := s.raw.(net.Conn); ok {
		if err = conn.SetReadDeadline(time.Now().Add(connDeadline)); err != nil {
			return
		}
	}
	vcEnc := make([]byte, 8)
	s.r.S.XORKeyStream(vcEnc, vc)
	err = s.readSync(vcEnc, 616-firstRead)
	if err != nil {
		return
	}
	debugln("--- out: reading crypto_select")
	err = binary.Read(s.r, binary.BigEndian, &selected)
	if err != nil {
		return
	}
	debugln("--- out: done")
	debugf("--- out: selected: %#v\n", selected)
	if selected == 0 {
		err = errors.New("none of the provided methods are accepted")
		return
	}
	if !isPowerOfTwo(uint32(selected)) {
		err = fmt.Errorf("invalid crypto selected: %d", selected)
		return
	}
	if (selected & cryptoProvide) == 0 {
		err = fmt.Errorf("selected crypto was not provided: %d", selected)
		return
	}
	var lenPadD uint16
	err = binary.Read(s.r, binary.BigEndian, &lenPadD)
	if err != nil {
		return
	}
	debugf("--- out: lenPadD: %d\n", lenPadD)
	_, err = io.CopyN(ioutil.Discard, s.r, int64(lenPadD))
	if err != nil {
		return
	}
	s.updateCipher(selected)

	debugln("--- out: end handshake")
	if conn, ok := s.raw.(net.Conn); ok {
		err = conn.SetDeadline(time.Time{})
	}
	return
	// Step 5 | A->B: ENCRYPT2(Payload Stream)
}

// HandshakeIncoming initiates MSE handshake for incoming connection.
//
// getSKey must return the correct stream identifier for given sKeyHash.
// sKeyHash can be calculated with mse.HashSKey function.
// If there is no matching sKeyHash in your application, you must return nil.
//
// cryptoSelect is a function that takes provided methods as a bitfield and returns the selected crypto method.
// Function may return zero value that means none of the provided methods are selected and handshake fails.
//
// payloadIn is a buffer for writing initial payload that is coming along with the handshake from the initiator of the connection.
// If initial payload does not fit into payloadIn, handshake returns io.ErrShortBuffer.
//
// lenPayloadIn is lenght of the data read into payloadIn.
//
// processPayloadIn is an optional function that processes incoming initial payload and generate outgoing initial payload.
// If this function returns an error, handshake fails.
func (s *Stream) HandshakeIncoming(
	getSKey func(sKeyHash [sha1.Size]byte) (sKey []byte),
	cryptoSelect func(provided CryptoMethod) (selected CryptoMethod),
	payloadIn []byte,
	lenPayloadIn *uint16,
	processPayloadIn func() (payloadOut []byte, err error)) (err error) {

	defer func() {
		if err != nil {
			if c, ok := s.raw.(io.Closer); ok {
				c.Close()
			}
		}
	}()

	writeBuf := bytes.NewBuffer(make([]byte, 0, 96+512))

	Xb, Yb, err := keyPair()
	if err != nil {
		return
	}

	// Step 1 | A->B: Diffie Hellman Ya, PadA
	if conn, ok := s.raw.(net.Conn); ok {
		if err = conn.SetReadDeadline(time.Now().Add(connDeadline)); err != nil {
			return
		}
	}
	b := make([]byte, 96+512)
	debugln("--- in: read PubkeyA")
	firstRead, err := io.ReadAtLeast(s.raw, b, 96)
	debugln("--- in: done")
	debugf("--- out: firstRead: %d\n", firstRead)
	if err != nil {
		return
	}
	Ya := new(big.Int)
	Ya.SetBytes(b[:96])
	S := Ya.Exp(Ya, Xb, p)

	// Step 2 | B->A: Diffie Hellman Yb, PadB
	if conn, ok := s.raw.(net.Conn); ok {
		if err = conn.SetWriteDeadline(time.Now().Add(connDeadline)); err != nil {
			return
		}
	}
	writeBuf.Write(bytesWithPad(Yb))
	padB, err := padRandom()
	if err != nil {
		return
	}
	writeBuf.Write(padB)
	debugln("--- in: writing Step 2")
	_, err = writeBuf.WriteTo(s.raw)
	if err != nil {
		return
	}
	debugln("--- in: done")

	// Step 3 | A->B: HASH('req1', S), HASH('req2', SKEY) xor HASH('req3', S), ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA)), ENCRYPT(IA)
	if conn, ok := s.raw.(net.Conn); ok {
		if err = conn.SetReadDeadline(time.Now().Add(connDeadline)); err != nil {
			return
		}
	}
	req1 := hashInt("req1", S)
	err = s.readSync(req1, 628-firstRead)
	if err != nil {
		return
	}
	var hashRead [sha1.Size]byte
	_, err = io.ReadFull(s.raw, hashRead[:])
	if err != nil {
		return
	}
	req3 := hashInt("req3", S)
	for i := 0; i < sha1.Size; i++ {
		hashRead[i] ^= req3[i]
	}
	sKey := getSKey(hashRead)
	if sKey == nil {
		err = errors.New("invalid SKEY hash")
		return
	}
	err = s.initRC4("keyB", "keyA", S, sKey)
	if err != nil {
		return
	}
	vcRead := make([]byte, 8)
	debugln("--- in: read vc")
	_, err = io.ReadFull(s.r, vcRead)
	if err != nil {
		return
	}
	debugln("--- in: done")
	if !bytes.Equal(vcRead, vc) {
		err = fmt.Errorf("invalid VC: %s", hex.EncodeToString(vcRead))
		return
	}
	var cryptoProvide CryptoMethod
	err = binary.Read(s.r, binary.BigEndian, &cryptoProvide)
	if err != nil {
		return
	}
	if cryptoProvide == 0 {
		err = errors.New("no crypto methods are provided")
		return
	}
	selected := cryptoSelect(cryptoProvide)
	if selected == 0 {
		err = errors.New("none of the provided methods are accepted")
		return
	}
	if !isPowerOfTwo(uint32(selected)) {
		err = fmt.Errorf("invalid crypto selected: %d", selected)
		return
	}
	if (selected & cryptoProvide) == 0 {
		err = fmt.Errorf("selected crypto is not provided: %d", selected)
		return
	}
	var lenPadC uint16
	err = binary.Read(s.r, binary.BigEndian, &lenPadC)
	if err != nil {
		return
	}
	_, err = io.CopyN(ioutil.Discard, s.r, int64(lenPadC))
	if err != nil {
		return
	}
	var lenIA uint16
	err = binary.Read(s.r, binary.BigEndian, &lenIA)
	if err != nil {
		return
	}
	if len(payloadIn) < int(lenIA) {
		err = io.ErrShortBuffer
		return
	}
	n, err := io.ReadFull(s.r, payloadIn[:int(lenIA)])
	if err != nil {
		return
	}
	*lenPayloadIn = uint16(n)
	payloadOut, err := processPayloadIn()
	if err != nil {
		return
	}

	// Step 4 | B->A: ENCRYPT(VC, crypto_select, len(padD), padD), ENCRYPT2(Payload Stream)
	if conn, ok := s.raw.(net.Conn); ok {
		if err = conn.SetWriteDeadline(time.Now().Add(connDeadline)); err != nil {
			return
		}
	}
	debugln("--- in: begin step 4")
	writeBuf.Write(vc)
	binary.Write(writeBuf, binary.BigEndian, selected)
	padD, err := padZero()
	if err != nil {
		return
	}
	binary.Write(writeBuf, binary.BigEndian, uint16(len(padD)))
	writeBuf.Write(padD)
	enc2Start := writeBuf.Len()
	debugf("--- in: enc2Start: %#v\n", enc2Start)
	writeBuf.Write(payloadOut)
	enc1Bytes := writeBuf.Bytes()[:enc2Start]
	enc2Bytes := writeBuf.Bytes()[enc2Start:]
	s.w.S.XORKeyStream(enc1Bytes, enc1Bytes) // RC4
	s.updateCipher(selected)
	s.w.S.XORKeyStream(enc2Bytes, enc2Bytes) // selected cipher
	debugln("--- in: writing step 4")
	_, err = writeBuf.WriteTo(s.raw)
	if err != nil {
		return
	}
	debugln("--- in: done")

	debugln("--- in: end handshake")
	if conn, ok := s.raw.(net.Conn); ok {
		err = conn.SetDeadline(time.Time{})
	}
	return
	// Step 5 | A->B: ENCRYPT2(Payload Stream)
}

var discard = make([]byte, 1024)

func (s *Stream) initRC4(encKey, decKey string, S *big.Int, sKey []byte) error {
	cipherEnc, err := rc4.NewCipher(rc4Key(encKey, S, sKey))
	if err != nil {
		return err
	}
	cipherDec, err := rc4.NewCipher(rc4Key(decKey, S, sKey))
	if err != nil {
		return err
	}
	cipherEnc.XORKeyStream(discard, discard)
	cipherDec.XORKeyStream(discard, discard)
	s.w = &cipher.StreamWriter{S: cipherEnc, W: s.raw}
	s.r = &cipher.StreamReader{S: cipherDec, R: s.raw}
	return nil
}

func (s *Stream) updateCipher(selected CryptoMethod) {
	switch selected {
	case RC4:
	case PlainText:
		s.r = &cipher.StreamReader{S: plainTextCipher{}, R: s.raw}
		s.w = &cipher.StreamWriter{S: plainTextCipher{}, W: s.raw}
	}
}

func (s *Stream) readSync(key []byte, max int) error {
	var readBuf bytes.Buffer
	if _, err := io.CopyN(&readBuf, s.raw, int64(len(key))); err != nil {
		return err
	}
	max -= len(key)
	for {
		if bytes.Equal(readBuf.Bytes(), key) {
			return nil
		}
		if max <= 0 {
			return errors.New("sync point is not found")
		}
		if _, err := io.CopyN(&readBuf, s.raw, 1); err != nil {
			return err
		}
		max--
		io.CopyN(ioutil.Discard, &readBuf, 1)
	}
}

func privateKey() (*big.Int, error) {
	b := make([]byte, 20)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	var n big.Int
	return n.SetBytes(b), nil
}

func publicKey(private *big.Int) *big.Int {
	var n big.Int
	return n.Exp(g, private, p)
}

func keyPair() (private, public *big.Int, err error) {
	private, err = privateKey()
	if err != nil {
		return
	}
	public = publicKey(private)
	return
}

// bytesWithPad adds padding in front of the bytes to fill 96 bytes.
func bytesWithPad(key *big.Int) []byte {
	b := key.Bytes()
	pad := 96 - len(b)
	if pad > 0 {
		b = make([]byte, 96)
		copy(b[pad:], key.Bytes())
	}
	return b
}

func isPowerOfTwo(x uint32) bool { return (x != 0) && ((x & (x - 1)) == 0) }

func hashes(S *big.Int, sKey []byte) (hashS, hashSKey []byte) {
	req1 := hashInt("req1", S)
	req2 := HashSKey(sKey)
	req3 := hashInt("req3", S)
	for i := 0; i < sha1.Size; i++ {
		req3[i] ^= req2[i]
	}
	return req1, req3
}

func hashInt(prefix string, i *big.Int) []byte {
	h := sha1.New()
	h.Write([]byte(prefix))
	h.Write(bytesWithPad(i))
	return h.Sum(nil)
}

func HashSKey(key []byte) [sha1.Size]byte {
	var sum [sha1.Size]byte
	h := sha1.New()
	h.Write([]byte("req2"))
	h.Write(key)
	copy(sum[:], h.Sum(nil))
	return sum
}

func rc4Key(prefix string, S *big.Int, sKey []byte) []byte {
	h := sha1.New()
	h.Write([]byte(prefix))
	h.Write(bytesWithPad(S))
	h.Write(sKey)
	return h.Sum(nil)
}

func padRandom() ([]byte, error) {
	b, err := padZero()
	if err != nil {
		return nil, err
	}
	_, err = rand.Read(b)
	return b, err
}

func padZero() ([]byte, error) {
	padLen, err := rand.Int(rand.Reader, big.NewInt(512))
	if err != nil {
		return nil, err
	}
	return make([]byte, int(padLen.Int64())), nil
}

type plainTextCipher struct{}

func (plainTextCipher) XORKeyStream(dst, src []byte) { copy(dst, src) }
