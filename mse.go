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
	"bufio"
	"bytes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
)

// TODO seed rands

const (
	// p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563
	p            = 0xDEADBEEFDEADBEEF // TODO change this
	pSize        = 8                  // bytes TODO should be 96
	g            = 2
	sKey  uint64 = 1234 // TODO make it variable
)

var vc = make([]byte, 8)

type CryptoMethod uint32

// Crypto methods
const (
	PlainText CryptoMethod = 1 << iota
	RC4
)

const (
	part1_size           = 20 + 28
	part2_size           = 20
	handshake_size       = part1_size + part2_size
	enc_negotiation_size = 8 + 4 + 2
	enc_pad_size         = 512
	enc_pad_read_size    = 96 + enc_pad_size + 20
	buffer_size          = enc_pad_read_size + 20 + enc_negotiation_size + enc_pad_size + 2 + handshake_size + 5
)

type Stream struct {
	raw io.ReadWriter
	// TODO remove x and y from struct
	x uint64 // private key // TODO must be 160 bits
	y uint64 // public key
	r io.Reader
	w io.Writer
}

func NewStream(rw io.ReadWriter) *Stream {
	s := Stream{
		raw: rw,
		x:   uint64(rand.Int63()),
	}
	s.y = (g ^ s.x) % p
	return &s
}

func (s *Stream) Read(p []byte) (n int, err error)  { return s.r.Read(p) }
func (s *Stream) Write(p []byte) (n int, err error) { return s.w.Write(p) }

func (s *Stream) HandshakeOutgoing(cryptoProvide CryptoMethod) (selected CryptoMethod, err error) {
	writeBuf := bufio.NewWriter(s.raw)

	// Step 1 | A->B: Diffie Hellman Ya, PadA
	err = binary.Write(writeBuf, binary.BigEndian, &s.y)
	if err != nil {
		return
	}
	padA, err := pad()
	if err != nil {
		return
	}
	_, err = writeBuf.Write(padA)
	if err != nil {
		return
	}
	err = writeBuf.Flush()
	if err != nil {
		return
	}

	// Step 2 | B->A: Diffie Hellman Yb, PadB
	readBuf := make([]byte, pSize+512)
	_, err = io.ReadAtLeast(s.raw, readBuf, pSize)
	if err != nil {
		return
	}
	var yRemote uint64
	err = binary.Read(bytes.NewReader(readBuf), binary.BigEndian, &yRemote)
	if err != nil {
		return
	}
	S := (yRemote ^ s.x) % p
	cipherEnc, err := rc4.NewCipher(rc4Key("keyA", S, sKey))
	if err != nil {
		return
	}
	cipherDec, err := rc4.NewCipher(rc4Key("keyB", S, sKey))
	if err != nil {
		return
	}
	discard := make([]byte, 1024)
	cipherEnc.XORKeyStream(discard, discard)
	cipherDec.XORKeyStream(discard, discard)
	s.w = cipher.StreamWriter{S: cipherEnc, W: s.raw}
	s.r = cipher.StreamReader{S: cipherDec, R: s.raw}

	// Step 3 | A->B: HASH('req1', S), HASH('req2', SKEY) xor HASH('req3', S), ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA)), ENCRYPT(IA)
	_, err = writeBuf.Write(hash("req1", S))
	if err != nil {
		return
	}
	req2 := hash("req2", sKey)
	req3 := hash("req3", S)
	for i := 0; i < sha1.Size; i++ {
		req2[i] ^= req3[i]
	}
	_, err = writeBuf.Write(req2)
	if err != nil {
		return
	}
	encBuf := bytes.NewBuffer(make([]byte, 0, 8+4+2+0+2))
	_, err = encBuf.Write(vc)
	if err != nil {
		return
	}
	err = binary.Write(encBuf, binary.BigEndian, cryptoProvide)
	if err != nil {
		return
	}
	err = binary.Write(encBuf, binary.BigEndian, uint16(0)) // len(PadC)
	if err != nil {
		return
	}
	err = binary.Write(encBuf, binary.BigEndian, uint16(0)) // len(IA)
	if err != nil {
		return
	}
	encBytes := encBuf.Bytes()
	cipherEnc.XORKeyStream(encBytes, encBytes)
	writeBuf.Write(encBytes)
	if err != nil {
		return
	}
	err = writeBuf.Flush()
	if err != nil {
		return
	}

	// Step 4 | B->A: ENCRYPT(VC, crypto_select, len(padD), padD), ENCRYPT2(Payload Stream)
	vcRead, err := s.decrypt(8)
	if err != nil {
		return
	}
	if bytes.Compare(vcRead, vc) != 0 {
		err = errors.New("invalid VC")
		return
	}
	cryptoSelect, err := s.decrypt(4)
	if err != nil {
		return
	}
	err = binary.Read(bytes.NewReader(cryptoSelect), binary.BigEndian, &selected)
	if err != nil {
		return
	}
	// TODO check selected crypto is provided
	lenPadDBytes, err := s.decrypt(2)
	if err != nil {
		return
	}
	var lenPadD uint16
	err = binary.Read(bytes.NewReader(lenPadDBytes), binary.BigEndian, &lenPadD)
	if err != nil {
		return
	}
	_, err = io.CopyN(ioutil.Discard, s.raw, int64(lenPadD))
	if err != nil {
		return
	}

	return selected, nil

	// Step 5 | A->B: ENCRYPT2(Payload Stream)
}

func (s *Stream) decrypt(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(s.r, buf)
	return buf, err
}

func hash(prefix string, key uint64) []byte {
	h := sha1.New()
	h.Write([]byte(prefix))
	binary.Write(h, binary.BigEndian, &key)
	return h.Sum(nil)
}

func rc4Key(prefix string, s uint64, sKey uint64) []byte {
	h := sha1.New()
	h.Write([]byte(prefix))
	binary.Write(h, binary.BigEndian, &s)
	binary.Write(h, binary.BigEndian, &sKey)
	return h.Sum(nil)
}

func pad() ([]byte, error) {
	b := make([]byte, rand.Intn(512))
	_, err := crand.Read(b)
	return b, err
}

func (s *Stream) HandshakeIncoming(cryptoSelect func(cryptoProvide CryptoMethod) (CryptoMethod, error)) error {
	// Step 1 | A->B: Diffie Hellman Ya, PadA
	readBuf := make([]byte, pSize+512)
	_, err := io.ReadAtLeast(s.raw, readBuf, pSize)
	if err != nil {
		return err
	}
	var yRemote uint64
	err = binary.Read(bytes.NewReader(readBuf), binary.BigEndian, &yRemote)
	if err != nil {
		return err
	}
	S := (yRemote ^ s.x) % p
	cipherEnc, err := rc4.NewCipher(rc4Key("keyB", S, sKey))
	if err != nil {
		return err
	}
	cipherDec, err := rc4.NewCipher(rc4Key("keyA", S, sKey))
	if err != nil {
		return err
	}
	discard := make([]byte, 1024)
	cipherEnc.XORKeyStream(discard, discard)
	cipherDec.XORKeyStream(discard, discard)
	s.w = cipher.StreamWriter{S: cipherEnc, W: s.raw}
	s.r = cipher.StreamReader{S: cipherDec, R: s.raw}

	// Step 2 | B->A: Diffie Hellman Yb, PadB
	writeBuf := bufio.NewWriter(s.raw)
	err = binary.Write(writeBuf, binary.BigEndian, &s.y)
	if err != nil {
		return err
	}
	padB, err := pad()
	_, err = writeBuf.Write(padB)
	if err != nil {
		return err
	}
	err = writeBuf.Flush()
	if err != nil {
		return err
	}

	// Step 3 | A->B: HASH('req1', S), HASH('req2', SKEY) xor HASH('req3', S), ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA)), ENCRYPT(IA)
	hashRead := make([]byte, 20)
	_, err = io.ReadFull(s.raw, hashRead)
	if err != nil {
		return err
	}
	hash1Calc := hash("req1", S)
	if !bytes.Equal(hashRead, hash1Calc) {
		err = errors.New("invalid S hash")
	}
	_, err = io.ReadFull(s.raw, hashRead)
	if err != nil {
		return err
	}
	hash2Calc := hash("req2", sKey)
	hash3Calc := hash("req3", S)
	for i := 0; i < sha1.Size; i++ {
		hash3Calc[i] ^= hash2Calc[i]
	}
	if !bytes.Equal(hashRead, hash3Calc) {
		err = errors.New("invalid SKEY hash")
	}
	vcRead, err := s.decrypt(8)
	if err != nil {
		return err
	}
	if !bytes.Equal(vcRead, vc) {
		return fmt.Errorf("invalid VC: %s", hex.EncodeToString(vcRead))
	}
	cryptoProvideBytes, err := s.decrypt(4)
	if err != nil {
		return err
	}
	var cryptoProvide CryptoMethod
	err = binary.Read(bytes.NewReader(cryptoProvideBytes), binary.BigEndian, &cryptoProvide)
	if err != nil {
		return err
	}
	selected, err := cryptoSelect(cryptoProvide)
	if err != nil {
		return err
	}
	_, err = io.CopyN(ioutil.Discard, s.raw, 4) // TODO padC and IA
	if err != nil {
		return err
	}

	// Step 4 | B->A: ENCRYPT(VC, crypto_select, len(padD), padD), ENCRYPT2(Payload Stream)
	encBuf := bytes.NewBuffer(make([]byte, 0, 8+4+2))
	_, err = encBuf.Write(vc)
	if err != nil {
		return err
	}
	err = binary.Write(encBuf, binary.BigEndian, selected)
	if err != nil {
		return err
	}
	err = binary.Write(encBuf, binary.BigEndian, uint16(0)) // len(PadC)
	if err != nil {
		return err
	}
	encBytes := encBuf.Bytes()
	cipherEnc.XORKeyStream(encBytes, encBytes)
	writeBuf.Write(encBytes)
	if err != nil {
		return err
	}
	err = writeBuf.Flush()
	if err != nil {
		return err
	}

	// Step 5 | A->B: ENCRYPT2(Payload Stream)
	return nil
}
