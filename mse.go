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
)

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

// Stream wraps a io.ReadWriter that automatically does encrypt/decrypt on read/write.
type Stream struct {
	raw io.ReadWriter
	r   *cipher.StreamReader
	w   *cipher.StreamWriter
}

// NewStream returns a new Stream. You must call HandshakeIncoming or
// HandshakeOutgoing methods before using Read/Write methods.
func NewStream(rw io.ReadWriter) *Stream { return &Stream{raw: rw} }

func (s *Stream) Read(p []byte) (n int, err error)  { return s.r.Read(p) }
func (s *Stream) Write(p []byte) (n int, err error) { return s.w.Write(p) }

// HandshakeOutgoing initiates MSE handshake for outgoing connection.
// If any error happens during the handshake underlying io.ReadWriter will be closed if it implements io.Closer.
func (s *Stream) HandshakeOutgoing(sKey []byte, cryptoProvide CryptoMethod, initialPayloadOutgoing []byte) (selected CryptoMethod, err error) {
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
	if len(initialPayloadOutgoing) > math.MaxUint16 {
		err = errors.New("initial payload is too big")
		return
	}

	writeBuf := bytes.NewBuffer(make([]byte, 0, 96+512))

	Xa, Ya, err := keyPair()
	if err != nil {
		return
	}

	// Step 1 | A->B: Diffie Hellman Ya, PadA
	writeBuf.Write(keyBytesWithPad(Ya))
	padA, err := pad()
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
	b := make([]byte, 96+512)
	debugln("--- out: reading PubkeyB")
	firstRead, err := io.ReadAtLeast(s.raw, b, 96)
	if err != nil {
		return
	}
	debugln("--- out: done")
	debugf("--- out: firstRead: %d\n", firstRead)
	Yb := new(big.Int)
	Yb.SetBytes(b[:96])
	S := Yb.Exp(Yb, Xa, p)
	err = s.initRC4("keyA", "keyB", S, sKey)
	if err != nil {
		return
	}

	// Step 3 | A->B: HASH('req1', S), HASH('req2', SKEY) xor HASH('req3', S), ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA)), ENCRYPT(IA)
	hashS, hashSKey := hashes(S, sKey)
	padC, err := pad()
	if err != nil {
		return
	}
	writeBuf.Write(hashS)
	writeBuf.Write(hashSKey)
	writeBuf.Write(vc)
	binary.Write(writeBuf, binary.BigEndian, cryptoProvide)
	binary.Write(writeBuf, binary.BigEndian, uint16(len(padC)))
	writeBuf.Write(padC)
	binary.Write(writeBuf, binary.BigEndian, uint16(len(initialPayloadOutgoing)))
	writeBuf.Write(initialPayloadOutgoing)
	encBytes := writeBuf.Bytes()[40:]
	s.w.S.XORKeyStream(encBytes, encBytes) // RC4
	debugln("--- out: writing Step 3")
	_, err = writeBuf.WriteTo(s.raw)
	if err != nil {
		return
	}
	debugln("--- out: done")

	// Step 4 | B->A: ENCRYPT(VC, crypto_select, len(padD), padD), ENCRYPT2(Payload Stream)
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
		err = fmt.Errorf("selected crypto is not provided: %d", selected)
		return
	}
	var lenPadD uint16
	err = binary.Read(s.r, binary.BigEndian, &lenPadD)
	if err != nil {
		return
	}
	_, err = io.CopyN(ioutil.Discard, s.r, int64(lenPadD))
	if err != nil {
		return
	}
	s.updateCipher(selected)

	debugln("--- out: end handshake")
	return
	// Step 5 | A->B: ENCRYPT2(Payload Stream)
}

// HandshakeIncoming initiates MSE handshake for incoming connection.
// If any error happens during the handshake underlying io.ReadWriter will be closed if it implements io.Closer.
func (s *Stream) HandshakeIncoming(sKey []byte, cryptoSelect func(provided CryptoMethod) (selected CryptoMethod), initialPayloadIncoming, initialPayloadOutgoing []byte) (n int, err error) {
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
	b := make([]byte, 96+512)
	debugln("--- in: read PubkeyA")
	firstRead, err := io.ReadAtLeast(s.raw, b, 96)
	if err != nil {
		return
	}
	debugln("--- in: done")
	Ya := new(big.Int)
	Ya.SetBytes(b[:96])
	S := Ya.Exp(Ya, Xb, p)
	err = s.initRC4("keyB", "keyA", S, sKey)
	if err != nil {
		return
	}

	// Step 2 | B->A: Diffie Hellman Yb, PadB
	writeBuf.Write(keyBytesWithPad(Yb))
	padB, err := pad()
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
	hashS, hashSKey := hashes(S, sKey)
	err = s.readSync(hashS, 628-firstRead)
	if err != nil {
		return
	}
	hashRead := make([]byte, 20)
	_, err = io.ReadFull(s.raw, hashRead)
	if err != nil {
		return
	}
	if !bytes.Equal(hashRead, hashSKey) {
		err = errors.New("invalid SKEY hash")
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
	if len(initialPayloadIncoming) < int(lenIA) {
		err = io.ErrShortBuffer
		return
	}
	n, err = io.ReadFull(s.r, initialPayloadIncoming[:int(lenIA)])
	if err != nil {
		return
	}

	// Step 4 | B->A: ENCRYPT(VC, crypto_select, len(padD), padD), ENCRYPT2(Payload Stream)
	debugln("--- in: begin step 4")
	writeBuf.Write(vc)
	binary.Write(writeBuf, binary.BigEndian, selected)
	padD, err := pad()
	if err != nil {
		return
	}
	binary.Write(writeBuf, binary.BigEndian, uint16(len(padD)))
	writeBuf.Write(padD)
	enc2Start := writeBuf.Len()
	debugf("--- in: enc2Start: %#v\n", enc2Start)
	writeBuf.Write(initialPayloadOutgoing)
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
	return
	// Step 5 | A->B: ENCRYPT2(Payload Stream)
}

func (s *Stream) initRC4(encKey, decKey string, S *big.Int, sKey []byte) error {
	cipherEnc, err := rc4.NewCipher(rc4Key(encKey, S, sKey))
	if err != nil {
		return err
	}
	cipherDec, err := rc4.NewCipher(rc4Key(decKey, S, sKey))
	if err != nil {
		return err
	}
	discard := make([]byte, 1024)
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

func keyBytesWithPad(key *big.Int) []byte {
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
	req1 := hashKey("req1", S)
	req2 := hashBytes("req2", sKey)
	req3 := hashKey("req3", S)
	for i := 0; i < sha1.Size; i++ {
		req3[i] ^= req2[i]
	}
	return req1, req3
}

func hashKey(prefix string, key *big.Int) []byte {
	h := sha1.New()
	h.Write([]byte(prefix))
	h.Write(keyBytesWithPad(key))
	return h.Sum(nil)
}

func hashBytes(prefix string, key []byte) []byte {
	h := sha1.New()
	h.Write([]byte(prefix))
	h.Write(key)
	return h.Sum(nil)
}

func rc4Key(prefix string, S *big.Int, sKey []byte) []byte {
	h := sha1.New()
	h.Write([]byte(prefix))
	h.Write(keyBytesWithPad(S))
	h.Write(sKey)
	return h.Sum(nil)
}

func pad() ([]byte, error) {
	padLen, err := rand.Int(rand.Reader, big.NewInt(512))
	if err != nil {
		return nil, err
	}
	b := make([]byte, int(padLen.Int64()))
	_, err = rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

type plainTextCipher struct{}

func (plainTextCipher) XORKeyStream(dst, src []byte) { copy(dst, src) }
