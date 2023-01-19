// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package capture formats packet logging into a debug pcap stream.
package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"sync"
	"time"

	_ "embed"
)

//go:embed ts-dissector.lua
var DissectorLua string

const flushPeriod = 100 * time.Millisecond

func writePcapHeader(w io.Writer) {
	binary.Write(w, binary.LittleEndian, uint32(0xA1B2C3D4)) // pcap magic number
	binary.Write(w, binary.LittleEndian, uint16(2))          // version major
	binary.Write(w, binary.LittleEndian, uint16(4))          // version minor
	binary.Write(w, binary.LittleEndian, uint32(0))          // this zone
	binary.Write(w, binary.LittleEndian, uint32(0))          // zone significant figures
	binary.Write(w, binary.LittleEndian, uint32(65535))      // max packet len
	binary.Write(w, binary.LittleEndian, uint32(147))        // link-layer ID - USER0
}

func writePktHeader(w *bytes.Buffer, when time.Time, length int) {
	s := when.Unix()
	us := when.UnixMicro() - (s * 1000000)

	binary.Write(w, binary.LittleEndian, uint32(s))      // timestamp in seconds
	binary.Write(w, binary.LittleEndian, uint32(us))     // timestamp microseconds
	binary.Write(w, binary.LittleEndian, uint32(length)) // length present
	binary.Write(w, binary.LittleEndian, uint32(length)) // total length
}

// Path describes where in the data path the packet was captured.
type Path uint8

// Valid Path values.
const (
	// FromLocal indicates the packet was logged as it traversed the FromLocal path:
	// i.e.: A packet from the local system into the TUN.
	FromLocal Path = 0
	// FromPeer indicates the packet was logged upon reception from a remote peer.
	FromPeer Path = 1
	// SynthesizedToLocal indicates the packet was generated from within tailscaled,
	// and is being routed to the local machine's network stack.
	SynthesizedToLocal Path = 2
	// SynthesizedToPeer indicates the packet was generated from within tailscaled,
	// and is being routed to a remote Wireguard peer.
	SynthesizedToPeer Path = 3
)

// New creates a new capture sink.
func New() *Sink {
	ctx, c := context.WithCancel(context.Background())
	return &Sink{
		ctx:       ctx,
		ctxCancel: c,
		bufferPool: sync.Pool{
			New: func() any {
				return new(bytes.Buffer)
			},
		},
	}
}

// Type Sink handles callbacks with packets to be logged,
// formatting them into a pcap stream which is mirrored to
// all registered outputs.
type Sink struct {
	ctx       context.Context
	ctxCancel context.CancelFunc

	bufferPool sync.Pool

	mu         sync.Mutex
	outputs    []io.Writer
	flushTimer *time.Timer
}

// RegisterOutput connects an output to this sink, which
// will be written to with a pcap stream as packets are logged.
//
// If w implements io.Closer, it will be closed upon error
// or when the sink is closed. If w implements http.Flusher,
// it will be flushed periodically.
func (s *Sink) RegisterOutput(w io.Writer) {
	select {
	case <-s.ctx.Done():
		return
	default:
	}

	writePcapHeader(w)
	s.mu.Lock()
	s.outputs = append(s.outputs, w)
	s.mu.Unlock()
}

// Close shuts down the sink. Future calls to LogPacket
// are ignored, and any registered output that implements
// io.Closer is closed.
func (s *Sink) Close() error {
	s.ctxCancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flushTimer != nil {
		s.flushTimer.Stop() // t.C is drained by blocked goroutine
		s.flushTimer = nil
	}

	for _, o := range s.outputs {
		if o, ok := o.(io.Closer); ok {
			o.Close()
		}
	}
	s.outputs = nil
	return nil
}

// Wait blocks till the Sink is closed.
func (s *Sink) Wait() {
	<-s.ctx.Done()
}

// LogPacket is called to insert a packet into the capture.
//
// This function does not take ownership of the provided data slice.
func (s *Sink) LogPacket(path Path, when time.Time, data []byte) {
	select {
	case <-s.ctx.Done():
		return
	default:
	}

	b := s.bufferPool.Get().(*bytes.Buffer)
	b.Reset()
	b.Grow(16 + 2 + len(data)) // 16b pcap header + 2b custom data + len
	defer s.bufferPool.Put(b)

	writePktHeader(b, when, len(data)+2)
	// Custom tailscale debugging data
	binary.Write(b, binary.LittleEndian, uint16(path))
	b.Write(data)

	s.mu.Lock()
	defer s.mu.Unlock()

	var hadError []int
	for i, o := range s.outputs {
		if _, err := o.Write(b.Bytes()); err != nil {
			hadError = append(hadError, i)
			continue
		}
	}

	for i, outputIdx := range hadError {
		idx := outputIdx - i
		if o, ok := s.outputs[idx].(io.Closer); ok {
			o.Close()
		}
		s.outputs = append(s.outputs[:idx], s.outputs[idx+1:]...)
	}

	if s.flushTimer == nil {
		t := time.NewTimer(flushPeriod)
		s.flushTimer = t
		go func() {
			// We do not check ctx here as Close() will
			// stop the timer and unblock us.
			_, ok := <-t.C
			if !ok {
				return
			}

			s.mu.Lock()
			defer s.mu.Unlock()
			for _, o := range s.outputs {
				if f, ok := o.(http.Flusher); ok {
					f.Flush()
				}
			}
			s.flushTimer = nil
		}()
	}
}
