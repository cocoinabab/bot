//go:build windows

package main

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	winDivertFlagSniff = 0x0001
	pcapLinkTypeRaw    = 101 // Raw IPv4/IPv6 packet, no Ethernet header.
)

type pcapWriter struct {
	mu    sync.Mutex
	f     *os.File
	w     *bufio.Writer
	count uint64
}

func newPCAPWriter(path string) (*pcapWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	// Classic PCAP, little endian, microsecond timestamps.
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[8:12], 0)
	binary.LittleEndian.PutUint32(hdr[12:16], 0)
	binary.LittleEndian.PutUint32(hdr[16:20], maxPacketSize)
	binary.LittleEndian.PutUint32(hdr[20:24], pcapLinkTypeRaw)
	if _, err := w.Write(hdr); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &pcapWriter{f: f, w: w}, nil
}

func (p *pcapWriter) WritePacket(ts time.Time, pkt []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.w == nil {
		return nil
	}
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[0:4], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(rec[4:8], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:12], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(rec[12:16], uint32(len(pkt)))
	if _, err := p.w.Write(rec); err != nil {
		return err
	}
	if _, err := p.w.Write(pkt); err != nil {
		return err
	}
	p.count++
	if p.count%128 == 0 {
		return p.w.Flush()
	}
	return nil
}

func (p *pcapWriter) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.w != nil {
		_ = p.w.Flush()
		p.w = nil
	}
	if p.f != nil {
		_ = p.f.Sync()
		err := p.f.Close()
		p.f = nil
		return err
	}
	return nil
}

type wireIndexWriter struct {
	mu  sync.Mutex
	f   *os.File
	gz  *gzip.Writer
	enc *json.Encoder
	seq uint64
}

type wireRecord struct {
	Seq        uint64 `json:"seq"`
	Time       string `json:"time"`
	Phase      string `json:"phase"`
	Direction  string `json:"direction"`
	IfIdx      uint32 `json:"if_idx"`
	SubIfIdx   uint32 `json:"sub_if_idx"`
	PacketLen  int    `json:"packet_len"`
	Src        string `json:"src,omitempty"`
	Dst        string `json:"dst,omitempty"`
	UDPLen     int    `json:"udp_payload_len,omitempty"`
	RakNet     any    `json:"raknet,omitempty"`
	ParseError string `json:"parse_error,omitempty"`
}

func newWireIndexWriter(path string) (*wireIndexWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewWriterLevel(f, gzip.BestSpeed)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &wireIndexWriter{f: f, gz: gz, enc: json.NewEncoder(gz)}, nil
}

func (w *wireIndexWriter) Write(rec wireRecord) {
	rec.Seq = atomic.AddUint64(&w.seq, 1)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.enc != nil {
		_ = w.enc.Encode(rec)
	}
}

func (w *wireIndexWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.gz != nil {
		_ = w.gz.Close()
		w.gz = nil
	}
	if w.f != nil {
		_ = w.f.Sync()
		_ = w.f.Close()
		w.f = nil
	}
}

type sniffWorker struct {
	phase   string
	dll     *syscall.LazyDLL
	open    *syscall.LazyProc
	recv    *syscall.LazyProc
	closeFn *syscall.LazyProc
	h       syscall.Handle
	pcap    *pcapWriter
	index   *wireIndexWriter
	al      *appLogger
	closed  chan struct{}
	once    sync.Once
}

func newSniffWorker(phase string, priority int16, pcap *pcapWriter, index *wireIndexWriter, al *appLogger) (*sniffWorker, error) {
	dll := syscall.NewLazyDLL("WinDivert.dll")
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("cannot load WinDivert.dll for %s capture: %w", phase, err)
	}
	s := &sniffWorker{
		phase: phase, dll: dll,
		open: dll.NewProc("WinDivertOpen"), recv: dll.NewProc("WinDivertRecv"), closeFn: dll.NewProc("WinDivertClose"),
		pcap: pcap, index: index, al: al, closed: make(chan struct{}),
	}
	// Capture both Minecraft's original endpoint and the local MITM endpoint.
	filter := fmt.Sprintf("udp and (udp.SrcPort == 19132 or udp.DstPort == 19132 or udp.SrcPort == 19133 or udp.DstPort == 19133 or udp.SrcPort == %d or udp.DstPort == %d)", localProxyPort, localProxyPort)
	fp, _ := syscall.BytePtrFromString(filter)
	// int16 priority is passed in the low 16 bits.
	pri := uintptr(uint16(priority))
	h, _, e1 := s.open.Call(uintptr(unsafe.Pointer(fp)), uintptr(windivertLayerNetwork), pri, uintptr(winDivertFlagSniff))
	if h == 0 || h == ^uintptr(0) {
		if e1 != syscall.Errno(0) {
			return nil, fmt.Errorf("WinDivertOpen(%s sniff) failed: %w", phase, e1)
		}
		return nil, fmt.Errorf("WinDivertOpen(%s sniff) failed; run as Administrator", phase)
	}
	s.h = syscall.Handle(h)
	return s, nil
}

func (s *sniffWorker) Close() {
	s.once.Do(func() {
		close(s.closed)
		if s.h != 0 {
			s.closeFn.Call(uintptr(s.h))
		}
	})
}

func (s *sniffWorker) Run() {
	buf := make([]byte, maxPacketSize)
	for {
		select {
		case <-s.closed:
			return
		default:
		}
		var recvLen uint32
		var addr [windivertAddressSize]byte
		ok, _, e1 := s.recv.Call(
			uintptr(s.h),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&recvLen)),
			uintptr(unsafe.Pointer(&addr[0])),
		)
		if ok == 0 {
			select {
			case <-s.closed:
				return
			default:
			}
			if e1 != syscall.Errno(0) && s.al != nil {
				s.al.printf("[WIRE-%s-ERR] %v", strings.ToUpper(s.phase), e1)
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		ts := time.Now()
		pkt := append([]byte(nil), buf[:int(recvLen)]...)
		_ = s.pcap.WritePacket(ts, pkt)

		flags := binary.LittleEndian.Uint64(addr[8:16])
		outbound := (flags & (uint64(1) << 17)) != 0
		direction := "inbound"
		if outbound {
			direction = "outbound"
		}
		rec := wireRecord{
			Time:      ts.Format(time.RFC3339Nano),
			Phase:     s.phase,
			Direction: direction,
			IfIdx:     binary.LittleEndian.Uint32(addr[16:20]),
			SubIfIdx:  binary.LittleEndian.Uint32(addr[20:24]),
			PacketLen: len(pkt),
		}
		if u, ok := parseIPv4UDP(pkt); ok {
			rec.Src = u.Src.String()
			rec.Dst = u.Dst.String()
			rec.UDPLen = len(u.Payload)
			rec.RakNet = analyseRakNet(u.Payload)
		} else {
			rec.ParseError = "not IPv4 UDP or truncated"
		}
		s.index.Write(rec)
	}
}

type wireCapture struct {
	pre, post *sniffWorker
	prePCAP   *pcapWriter
	postPCAP  *pcapWriter
	index     *wireIndexWriter
	wg        sync.WaitGroup
	once      sync.Once
}

func newWireCapture(logDir, stamp string, al *appLogger) (*wireCapture, error) {
	prePath := filepath.Join(logDir, "wire-pre-"+stamp+".pcap")
	postPath := filepath.Join(logDir, "wire-post-"+stamp+".pcap")
	indexPath := filepath.Join(logDir, "wire-index-"+stamp+".jsonl.gz")
	prePCAP, err := newPCAPWriter(prePath)
	if err != nil {
		return nil, err
	}
	postPCAP, err := newPCAPWriter(postPath)
	if err != nil {
		_ = prePCAP.Close()
		return nil, err
	}
	idx, err := newWireIndexWriter(indexPath)
	if err != nil {
		_ = prePCAP.Close()
		_ = postPCAP.Close()
		return nil, err
	}
	// WinDivert uses lower numeric values as higher priority. -1000 sees packets before the redirector (priority 0); +1000 sees them after rewrite/reinjection.
	pre, err := newSniffWorker("pre", -1000, prePCAP, idx, al)
	if err != nil {
		idx.Close()
		_ = prePCAP.Close()
		_ = postPCAP.Close()
		return nil, err
	}
	post, err := newSniffWorker("post", 1000, postPCAP, idx, al)
	if err != nil {
		pre.Close()
		idx.Close()
		_ = prePCAP.Close()
		_ = postPCAP.Close()
		return nil, err
	}
	if al != nil {
		al.printf("[WIRE] pre-divert PCAP=%s", prePath)
		al.printf("[WIRE] post-divert PCAP=%s", postPath)
		al.printf("[WIRE] RakNet index=%s", indexPath)
	}
	return &wireCapture{pre: pre, post: post, prePCAP: prePCAP, postPCAP: postPCAP, index: idx}, nil
}

func (w *wireCapture) Start() {
	w.wg.Add(2)
	go func() { defer w.wg.Done(); w.pre.Run() }()
	go func() { defer w.wg.Done(); w.post.Run() }()
}

func (w *wireCapture) Close() {
	w.once.Do(func() {
		if w.pre != nil {
			w.pre.Close()
		}
		if w.post != nil {
			w.post.Close()
		}
		w.wg.Wait()
		if w.prePCAP != nil {
			_ = w.prePCAP.Close()
		}
		if w.postPCAP != nil {
			_ = w.postPCAP.Close()
		}
		if w.index != nil {
			w.index.Close()
		}
	})
}

func triadLE(b []byte) uint32 {
	if len(b) < 3 {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
}

func rakNetPacketName(id byte) string {
	switch id {
	case 0x00:
		return "ConnectedPing"
	case 0x01:
		return "UnconnectedPing"
	case 0x03:
		return "ConnectedPong"
	case 0x05:
		return "OpenConnectionRequest1"
	case 0x06:
		return "OpenConnectionReply1"
	case 0x07:
		return "OpenConnectionRequest2"
	case 0x08:
		return "OpenConnectionReply2"
	case 0x09:
		return "ConnectionRequest"
	case 0x10:
		return "ConnectionRequestAccepted"
	case 0x13:
		return "NewIncomingConnection"
	case 0x15:
		return "DisconnectionNotification"
	case 0x1c:
		return "UnconnectedPong"
	case 0xa0:
		return "NAK"
	case 0xc0:
		return "ACK"
	}
	if id >= 0x80 && id <= 0x8f {
		return "Datagram"
	}
	return fmt.Sprintf("RakNet/Unknown(0x%02X)", id)
}

func reliabilityName(r byte) string {
	switch r {
	case 0:
		return "Unreliable"
	case 1:
		return "UnreliableSequenced"
	case 2:
		return "Reliable"
	case 3:
		return "ReliableOrdered"
	case 4:
		return "ReliableSequenced"
	case 5:
		return "UnreliableWithAckReceipt"
	case 6:
		return "ReliableWithAckReceipt"
	case 7:
		return "ReliableOrderedWithAckReceipt"
	default:
		return fmt.Sprintf("Unknown(%d)", r)
	}
}

func analyseRakNet(payload []byte) any {
	if len(payload) == 0 {
		return nil
	}
	id := payload[0]
	out := map[string]any{"id": id, "name": rakNetPacketName(id), "len": len(payload)}
	switch {
	case id == 0x05: // Request1 is padded to the selected MTU minus IPv4+UDP headers.
		if len(payload) >= 18 {
			out["protocol_version"] = payload[17]
		}
		out["mtu_estimate_ipv4"] = len(payload) + 28
	case id == 0x06:
		if len(payload) >= 28 {
			out["mtu"] = binary.BigEndian.Uint16(payload[26:28])
		}
	case id == 0x07:
		// IPv4 server address encoding is 7 bytes after magic.
		if len(payload) >= 26 && payload[17] == 4 {
			out["mtu"] = binary.BigEndian.Uint16(payload[24:26])
		}
	case id == 0x08:
		if len(payload) >= 34 && payload[25] == 4 {
			out["mtu"] = binary.BigEndian.Uint16(payload[32:34])
		}
	case id == 0xa0 || id == 0xc0:
		out["records"] = parseAckNak(payload)
	case id >= 0x80 && id <= 0x8f:
		if len(payload) >= 4 {
			out["datagram_sequence"] = triadLE(payload[1:4])
			out["frames"] = parseRakNetFrames(payload[4:])
		}
	}
	return out
}

func parseAckNak(payload []byte) []any {
	if len(payload) < 3 {
		return nil
	}
	count := int(binary.BigEndian.Uint16(payload[1:3]))
	off := 3
	out := make([]any, 0, count)
	for i := 0; i < count && off < len(payload); i++ {
		single := payload[off] != 0
		off++
		if single {
			if off+3 > len(payload) {
				break
			}
			seq := triadLE(payload[off : off+3])
			off += 3
			out = append(out, map[string]any{"single": true, "sequence": seq})
		} else {
			if off+6 > len(payload) {
				break
			}
			min := triadLE(payload[off : off+3])
			max := triadLE(payload[off+3 : off+6])
			off += 6
			out = append(out, map[string]any{"single": false, "min": min, "max": max})
		}
	}
	return out
}

func parseRakNetFrames(data []byte) []any {
	out := make([]any, 0, 4)
	off := 0
	for off+3 <= len(data) {
		start := off
		flags := data[off]
		off++
		rel := flags >> 5
		split := (flags & 0x10) != 0
		bitLen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		byteLen := (bitLen + 7) / 8
		f := map[string]any{"reliability": rel, "reliability_name": reliabilityName(rel), "split": split, "bit_length": bitLen, "payload_length": byteLen}

		if rel == 2 || rel == 3 || rel == 4 || rel == 6 || rel == 7 {
			if off+3 > len(data) {
				f["parse_error"] = "truncated reliable index"
				out = append(out, f)
				break
			}
			f["message_index"] = triadLE(data[off : off+3])
			off += 3
		}
		if rel == 1 || rel == 4 {
			if off+3 > len(data) {
				f["parse_error"] = "truncated sequence index"
				out = append(out, f)
				break
			}
			f["sequence_index"] = triadLE(data[off : off+3])
			off += 3
		}
		if rel == 1 || rel == 3 || rel == 4 || rel == 7 {
			if off+4 > len(data) {
				f["parse_error"] = "truncated ordering index"
				out = append(out, f)
				break
			}
			f["ordering_index"] = triadLE(data[off : off+3])
			off += 3
			f["ordering_channel"] = data[off]
			off++
		}
		if split {
			if off+10 > len(data) {
				f["parse_error"] = "truncated split header"
				out = append(out, f)
				break
			}
			f["split_count"] = binary.BigEndian.Uint32(data[off : off+4])
			off += 4
			f["split_id"] = binary.BigEndian.Uint16(data[off : off+2])
			off += 2
			f["split_index"] = binary.BigEndian.Uint32(data[off : off+4])
			off += 4
		}
		if byteLen < 0 || off+byteLen > len(data) {
			f["parse_error"] = "truncated frame payload"
			f["remaining"] = len(data) - off
			out = append(out, f)
			break
		}
		body := data[off : off+byteLen]
		off += byteLen
		if len(body) > 0 {
			f["body_id"] = body[0]
			f["body_name"] = rakNetPacketName(body[0])
			preview := body
			if len(preview) > 48 {
				preview = preview[:48]
			}
			f["body_preview_hex"] = strings.ToUpper(hex.EncodeToString(preview))
		}
		f["frame_bytes"] = off - start
		out = append(out, f)
	}
	return out
}
