package mse

import "net"

type Conn struct {
	net.Conn
	*Stream
}

func WrapConn(conn net.Conn) *Conn {
	return &Conn{
		Conn:   conn,
		Stream: NewStream(conn),
	}
}

func (c *Conn) Read(p []byte) (n int, err error)  { return c.Stream.Read(p) }
func (c *Conn) Write(p []byte) (n int, err error) { return c.Stream.Write(p) }
