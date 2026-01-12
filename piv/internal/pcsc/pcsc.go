// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pcsc implements the libpcsclite protocol for communicating with pcscd.
//
// This package is a pure Go implementation of libpcsclite, allowing piv-go to
// communicate directly with pcscd without cgo. This still relies on pcscd to
// communicate with the OS, and will be less reliable than linking against the
// shared libraries provided by the pcscd packages.
//
// This package will NOT work with the native Mac and Windows libraries, which
// are provided directly by the OS. Though pcsclite can be installed on Mac.
package pcsc

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

// pcscd messages directly encode C structs over a unix domain socket. Determine
// the host's byte order with build tags so encoding/binary can replicate this
// behavior.
//
// https://groups.google.com/g/golang-nuts/c/3GEzwKfRRQw/m/ppkJKrT4cfAJ
var nativeByteOrder binary.ByteOrder

const (
	pcscSocketPathEnv = "PCSCLITE_CSOCK_NAME"
	pcscSocketPath    = "/run/pcscd/pcscd.comm"
)

const (
	// RVSuccess is a return value indicating the operation succeeded.
	RVSuccess = 0

	majorVersion = 4
	minorVersion = 4

	// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L76
	commandEstablishContext = 0x01
	commandReleaseContext   = 0x02
	commandConnect          = 0x04
	commandDisconnect       = 0x05
	commandBeginTransaction = 0x07
	commandEndTransaction   = 0x08
	commandTransmit         = 0x09
	commandVersion          = 0x11
	commandGetReadersState  = 0x12

	// Context modes to be passed to NewContext.
	//
	// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/PCSC/pcsclite.h.in#L248
	Exclusive = 0x0001
	Shared    = 0x0002
	Direct    = 0x0003

	// Different protocols that can be used when connecting to a card.
	ProtocolT0  = 0x0001
	ProtocolT1  = 0x0002
	ProtocolRaw = 0x0004
	ProtocolT15 = 0x0005

	// Disconnect option.
	LeaveCard   = 0x0000
	ResetCard   = 0x0001
	UnpowerCard = 0x0002
	EjectCard   = 0x0003
)

// RVError wraps an underlying PCSC error code.
type RVError struct {
	RV uint32
}

type scardContext uint32
type scardHandle uint32
type scardLong int32
type scardPad [0]byte

// Error returns a string encoding of the error code. Note that human readable
// messages are not provided by this package, and are handled by the piv
// package instead.
func (r *RVError) Error() string {
	return fmt.Sprintf("rv 0x%x", r.RV)
}

// Client represents a connection with the pcscd process.
type Client struct {
	conn         net.Conn
	versionMinor int32
}

// Close releases the underlying connection. It does not release any contexts
// which must be closed separately.
func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) checkVersion() error {
	req := struct {
		Major int32
		Minor int32
		RV    int32
	}{majorVersion, minorVersion, RVSuccess}

	body, err := c.sendMessageRaw(commandVersion, req, 12)
	if err != nil {
		return fmt.Errorf("send message: %v", err)
	}

	if len(body) == 4 {
		rv := nativeByteOrder.Uint32(body)
		if rv != RVSuccess {
			return &RVError{RV: rv}
		}
		return nil
	}

	var resp struct {
		Major int32
		Minor int32
		RV    int32
	}
	if err := binary.Read(bytes.NewReader(body), nativeByteOrder, &resp); err != nil {
		return fmt.Errorf("read version response: %v", err)
	}

	if resp.RV != RVSuccess {
		return &RVError{RV: uint32(resp.RV)}
	}
	if resp.Major != majorVersion {
		return fmt.Errorf("unsupported major version of pcscd protocol: %d", resp.Major)
	}
	c.versionMinor = resp.Minor
	return nil
}

const (
	// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/PCSC/pcsclite.h.in#L286
	maxReaderNameSize = 128
	// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/PCSC/pcsclite.h.in#L59
	maxAttributeSize = 33
	// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/PCSC/pcsclite.h.in#L284
	maxReaders = 16
)

// readerState holds metadata about a PCSC card.
//
// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/eventhandler.h#L52
type readerState struct {
	Name         [maxReaderNameSize]byte
	EventCounter uint32
	State        uint32
	Sharing      int32

	Attr     [maxAttributeSize]byte
	Padding  [3]byte
	AttrSize uint32
	Protocol uint32
}

func (r readerState) name() string {
	if r.Name[0] == 0x00 {
		return ""
	}
	i := len(r.Name)
	for ; i > 0; i-- {
		if r.Name[i-1] != 0x00 {
			break
		}
	}
	return string(r.Name[:i])
}

// Readers returns the names of all readers that are connected to the device.
func (c *Client) Readers() ([]string, error) {
	resp, err := c.readers()
	if err != nil {
		return nil, err
	}

	var names []string
	for _, r := range resp {
		name := r.name()
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

func (c *Client) readers() (states [maxReaders]readerState, err error) {
	if err := c.sendMessage(commandGetReadersState, nil, &states); err != nil {
		return states, fmt.Errorf("send message: %v", err)
	}
	return states, nil
}

// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L118
type establishRequest struct {
	Scope   uint32
	Padding scardPad
	Context scardContext
	RV      scardLong
}

// Context holds an open PCSC context, which is required to perform actions
// such as starting transactions or transmitting data to a card.
type Context struct {
	client  *Client
	context scardContext
}

// NewContext attempts to establish a context with the PCSC daemon. The returned
// context is only valid while the client is open.
func (c *Client) NewContext() (*Context, error) {
	const scopeSystem = 0x0002
	req := establishRequest{
		Scope: scopeSystem,
		RV:    RVSuccess,
	}
	if err := c.sendMessage(commandEstablishContext, req, &req); err != nil {
		return nil, fmt.Errorf("establish context: %v", err)
	}
	if req.RV != RVSuccess {
		return nil, &RVError{RV: uint32(req.RV)}
	}
	return &Context{client: c, context: req.Context}, nil
}

// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L118
type releaseRequest struct {
	Context scardContext
	RV      scardLong
}

// Close releases the context with the PCSC daemon.
func (c *Context) Close() error {
	req := releaseRequest{
		Context: c.context,
		RV:      RVSuccess,
	}
	if err := c.client.sendMessage(commandReleaseContext, req, &req); err != nil {
		return fmt.Errorf("release context: %v", err)
	}
	if req.RV != RVSuccess {
		return &RVError{RV: uint32(req.RV)}
	}
	return nil
}

// Connection represents a connection to a specific smartcard.
type Connection struct {
	client   *Client
	context  scardContext
	card     scardHandle
	protocol uint32
}

// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L141
type connectRequest struct {
	Context            scardContext
	Reader             [maxReaderNameSize]byte
	ShareMode          uint32
	PreferredProtocols uint32
	Card               scardHandle
	ActiveProtocols    uint32
	Padding            scardPad
	RV                 scardLong
}

func (c *Context) Connect(reader string, mode uint32) (*Connection, error) {
	req := connectRequest{
		Context:            c.context,
		ShareMode:          mode,
		PreferredProtocols: ProtocolT1,
		RV:                 RVSuccess,
	}

	if len(reader)+1 > maxReaderNameSize {
		return nil, fmt.Errorf("reader name too long")
	}
	copy(req.Reader[:], []byte(reader))

	if err := c.client.sendMessage(commandConnect, req, &req); err != nil {
		return nil, fmt.Errorf("send message: %v", err)
	}
	if req.RV != RVSuccess {
		return nil, &RVError{RV: uint32(req.RV)}
	}
	if req.Card == 0 {
		return nil, fmt.Errorf("card returned no value")
	}
	return &Connection{
		client: c.client, context: c.context, card: req.Card, protocol: req.ActiveProtocols,
	}, nil
}

// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L172
type disconnectRequest struct {
	Card        scardHandle
	Disposition uint32
	Padding     scardPad
	RV          scardLong
}

func (c *Connection) Close() error {
	req := disconnectRequest{
		Card:        c.card,
		Disposition: LeaveCard,
		RV:          RVSuccess,
	}

	if err := c.client.sendMessage(commandDisconnect, req, &req); err != nil {
		return fmt.Errorf("send message: %v", err)
	}
	if req.RV != RVSuccess {
		return &RVError{RV: uint32(req.RV)}
	}
	return nil
}

// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L184
type beginRequest struct {
	Card scardHandle
	RV   scardLong
}

// BeginTransaction is called before transmitting data to the card.
func (c *Connection) BeginTransaction() error {
	req := beginRequest{
		Card: c.card,
		RV:   RVSuccess,
	}

	if err := c.client.sendMessage(commandBeginTransaction, req, &req); err != nil {
		return fmt.Errorf("send message: %v", err)
	}
	if req.RV != RVSuccess {
		return &RVError{RV: uint32(req.RV)}
	}
	return nil
}

// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L195
type endRequest struct {
	Card        scardHandle
	Disposition uint32
	Padding     scardPad
	RV          scardLong
}

func (c *Connection) EndTransaction() error {
	req := endRequest{
		Card:        c.card,
		Disposition: LeaveCard,
		RV:          RVSuccess,
	}

	if err := c.client.sendMessage(commandEndTransaction, req, &req); err != nil {
		return fmt.Errorf("send message: %v", err)
	}
	if req.RV != RVSuccess {
		return &RVError{RV: uint32(req.RV)}
	}
	return nil
}

// https://github.com/LudovicRousseau/PCSC/blob/1.9.0/src/winscard_msg.h#L207
type transmitRequest struct {
	Card              scardHandle
	IoSendPciProtocol uint32
	IoSendPciLength   uint32
	CbSendLength      uint32
	IoRecvPciProtocol uint32
	IoRecvPciLength   uint32
	PcbRecvLength     uint32
	RV                scardLong
}

type transmitRequestOld struct {
	IoSendPciProtocol uint32
	IoSendPciLength   uint32
	IoRecvPciProtocol uint32
	IoRecvPciLength   uint32
	CbSendLength      uint32
	PcbRecvLength     uint32
	Card              scardHandle
	RV                scardLong
}

func (c *Connection) Transmit(b []byte) ([]byte, error) {
	if c.client.versionMinor < 4 {
		return c.transmitOld(b)
	}

	req := transmitRequest{
		Card:              c.card,
		IoSendPciProtocol: c.protocol,
		IoSendPciLength:   8,
		CbSendLength:      uint32(len(b)),
		IoRecvPciProtocol: c.protocol,
		IoRecvPciLength:   8,
		PcbRecvLength:     65536 + 256,
		RV:                RVSuccess,
	}

	buf := &bytes.Buffer{}
	if err := binary.Write(buf, nativeByteOrder, req); err != nil {
		return nil, fmt.Errorf("marshaling transmit request: %v", err)
	}
	buf.Write(b)

	size := uint32(binary.Size(req))
	header := make([]byte, 8)
	nativeByteOrder.PutUint32(header[0:4], size)
	nativeByteOrder.PutUint32(header[4:8], commandTransmit)

	if _, err := c.client.conn.Write(header); err != nil {
		return nil, fmt.Errorf("writing transmit header: %v", err)
	}
	if _, err := c.client.conn.Write(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("writing transmit body: %v", err)
	}

	// Read response body safely using known struct size
	// We assume no header in response or fixed size response
	readingSize := uint32(binary.Size(req))
	body := make([]byte, readingSize)
	if _, err := io.ReadFull(c.client.conn, body); err != nil {
		return nil, fmt.Errorf("read response body: %v", err)
	}

	bufReader := bytes.NewReader(body)
	var resp transmitRequest
	if err := binary.Read(bufReader, nativeByteOrder, &resp); err != nil {
		return nil, fmt.Errorf("reading transmit response struct: %v (minor=%d, size=%d)", err, c.client.versionMinor, readingSize)
	}

	if resp.RV != RVSuccess {
		return nil, &RVError{RV: uint32(resp.RV)}
	}

	if resp.PcbRecvLength > 0 {
		data := make([]byte, resp.PcbRecvLength)
		if _, err := io.ReadFull(c.client.conn, data); err != nil {
			return nil, fmt.Errorf("reading transmit data: %v", err)
		}
		return data, nil
	}

	return []byte{}, nil
}

func (c *Connection) transmitOld(b []byte) ([]byte, error) {
	req := transmitRequestOld{
		IoSendPciProtocol: c.protocol,
		IoSendPciLength:   8,
		IoRecvPciProtocol: c.protocol,
		IoRecvPciLength:   8,
		CbSendLength:      uint32(len(b)),
		PcbRecvLength:     65536 + 256,
		Card:              c.card,
		RV:                RVSuccess,
	}

	buf := &bytes.Buffer{}
	if err := binary.Write(buf, nativeByteOrder, req); err != nil {
		return nil, fmt.Errorf("marshaling transmit request: %v", err)
	}
	buf.Write(b)

	size := uint32(buf.Len())
	header := make([]byte, 8)
	nativeByteOrder.PutUint32(header[0:4], size)
	nativeByteOrder.PutUint32(header[4:8], commandTransmit)

	if _, err := c.client.conn.Write(header); err != nil {
		return nil, fmt.Errorf("writing transmit header: %v", err)
	}
	if _, err := c.client.conn.Write(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("writing transmit body: %v", err)
	}

	readingSize := uint32(binary.Size(req))
	body := make([]byte, readingSize)
	if _, err := io.ReadFull(c.client.conn, body); err != nil {
		return nil, fmt.Errorf("read response body: %v", err)
	}

	bufReader := bytes.NewReader(body)
	var resp transmitRequestOld
	if err := binary.Read(bufReader, nativeByteOrder, &resp); err != nil {
		return nil, fmt.Errorf("reading transmit response struct: %v (minor=%d, size=%d)", err, c.client.versionMinor, readingSize)
	}

	if resp.RV != RVSuccess {
		return nil, &RVError{RV: uint32(resp.RV)}
	}

	if resp.PcbRecvLength > 0 {
		data := make([]byte, resp.PcbRecvLength)
		if _, err := io.ReadFull(c.client.conn, data); err != nil {
			return nil, fmt.Errorf("reading transmit data: %v", err)
		}
		return data, nil
	}

	return []byte{}, nil
}

func (c *Client) sendMessage(command uint32, req, resp interface{}) error {
	respSize := 0
	if resp != nil {
		respSize = binary.Size(resp)
	}
	body, err := c.sendMessageRaw(command, req, uint32(respSize))
	if err != nil {
		return err
	}
	if resp != nil {
		respData := bytes.NewReader(body)
		if err := binary.Read(respData, nativeByteOrder, resp); err != nil {
			return fmt.Errorf("read response: %v (got %d bytes), %w", err, len(body), err)
		}
	}
	return nil
}

func (c *Client) sendMessageRaw(command uint32, req interface{}, respSize uint32) ([]byte, error) {
	var data []byte
	if req != nil {
		b := &bytes.Buffer{}
		if err := binary.Write(b, nativeByteOrder, req); err != nil {
			return nil, fmt.Errorf("marshaling message body: %v", err)
		}

		size := uint32(b.Len())

		data = make([]byte, b.Len()+4+4)
		nativeByteOrder.PutUint32(data[0:4], size)
		nativeByteOrder.PutUint32(data[4:8], command)
		io.ReadFull(b, data[8:])
	} else {
		data = make([]byte, 4+4)
		nativeByteOrder.PutUint32(data[0:4], 0)
		nativeByteOrder.PutUint32(data[4:8], command)
	}

	if _, err := c.conn.Write(data); err != nil {
		return nil, fmt.Errorf("write request bytes: %v", err)
	}

	if respSize == 0 {
		return []byte{}, nil
	}

	body := make([]byte, respSize)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		return nil, fmt.Errorf("read response body: %v", err)
	}

	return body, nil
}

// Config is used to modify client behavior.
type Config struct {
	// SocketPath can be used to override a path to the pcscd socket. This field
	// is generally not required unless pcscd has been compiled with modified
	// options.
	//
	// This value defaults to the pcsclite behavior, preferring the value of the
	// PCSCLITE_CSOCK_NAME environment variable then defaulting to
	// "/run/pcscd/pcscd.comm".
	SocketPath string
}

// NewClient attempts to initialize a connection with pcscd. The context is used
// for dialing the unix domain socket.
func NewClient(ctx context.Context, c *Config) (*Client, error) {
	p := c.SocketPath
	if p == "" {
		p = os.Getenv(pcscSocketPathEnv)
	}
	if p == "" {
		p = pcscSocketPath
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", p)
	if err != nil {
		return nil, fmt.Errorf("dial unix socket: %v", err)
	}
	client := &Client{conn: conn}
	if err := client.checkVersion(); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}
