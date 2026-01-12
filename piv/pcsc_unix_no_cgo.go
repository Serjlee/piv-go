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

//go:build linux
// +build linux

package piv

import (
	"context"
	"errors"
	"fmt"

	"github.com/qubesome/piv-go/piv/internal/pcsc"
)

func scCheck(err error) error {
	var e *pcsc.RVError
	if errors.As(err, &e) {
		return &scErr{int64(e.RV)}
	}
	return err
}

const rcSuccess = pcsc.RVSuccess

type scContext struct {
	client *pcsc.Client
	ctx    *pcsc.Context
}

func newSCContext() (*scContext, error) {
	c, err := pcsc.NewClient(context.Background(), &pcsc.Config{})
	if err != nil {
		return nil, err
	}
	ctx, err := c.NewContext()
	if err != nil {
		c.Close()
		return nil, err
	}
	return &scContext{c, ctx}, nil
}

func (c *scContext) Close() error {
	err1 := c.ctx.Close()
	if err := c.client.Close(); err != nil {
		return err
	}
	return err1
}

func (c *scContext) ListReaders() ([]string, error) {
	return c.client.Readers()
}

type scHandle struct {
	conn *pcsc.Connection
}

func (c *scContext) Connect(reader string) (*scHandle, error) {
	conn, err := c.ctx.Connect(reader, pcsc.Exclusive)
	if err != nil {
		return nil, scCheck(err)
	}
	return &scHandle{conn}, nil
}

func (h *scHandle) Close() error {
	return scCheck(h.conn.Close())
}

type scTx struct {
	conn *pcsc.Connection
}

func (h *scHandle) Begin() (*scTx, error) {
	if err := h.conn.BeginTransaction(); err != nil {
		return nil, scCheck(err)
	}
	return &scTx{h.conn}, nil
}

func (t *scTx) Close() error {
	return scCheck(t.conn.EndTransaction())
}

func (t *scTx) transmit(req []byte) (more bool, b []byte, err error) {
	resp, err := t.conn.Transmit(req)
	if err != nil {
		return false, nil, scCheck(err)
	}

	if len(resp) < 2 {
		return false, nil, fmt.Errorf("scard response too short: %d", len(resp))
	}
	sw1 := resp[len(resp)-2]
	sw2 := resp[len(resp)-1]
	if sw1 == 0x90 && sw2 == 0x00 {
		return false, resp[:len(resp)-2], nil
	}
	if sw1 == 0x61 {
		return true, resp[:len(resp)-2], nil
	}
	return false, nil, &apduErr{sw1, sw2}
}
