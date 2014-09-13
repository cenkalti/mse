package mse_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/cenkalti/mse"
)

// Pipe2 is a bidirectional io.Pipe.
type Pipe2 struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p *Pipe2) Read(b []byte) (n int, err error) {
	return p.r.Read(b)
}

func (p *Pipe2) Write(b []byte) (n int, err error) {
	return p.w.Write(b)
}

func (p *Pipe2) Close() error {
	p.r.Close()
	p.w.Close()
	return nil
}

func NewPipe2() (*Pipe2, *Pipe2) {
	var a, b Pipe2
	a.r, b.w = io.Pipe()
	b.r, a.w = io.Pipe()
	return &a, &b
}

func TestPipe2(t *testing.T) {
	a, b := NewPipe2()

	err := testRws(a, b)
	if err != nil {
		t.Fatal(err)
	}
}

func TestStream(t *testing.T) {
	conn1, conn2 := NewPipe2()

	a := mse.NewStream(conn1)
	b := mse.NewStream(conn2)

	err := testRws(a, b)
	if err != nil {
		t.Fatal(err)
	}
}

func testRws(a, b io.ReadWriter) error {
	data := []byte("asdf")
	go a.Write(data)

	buf := make([]byte, 10)
	n, err := b.Read(buf)
	if err != nil {
		return err
	}
	if n != 4 {
		return fmt.Errorf("n must be 4, not %d", n)
	}
	if bytes.Compare(buf[:n], data) != 0 {
		return errors.New("invalid data received")
	}

	return nil
}
